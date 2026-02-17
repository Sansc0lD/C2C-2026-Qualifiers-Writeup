#include "server.hpp"
#include "http_utils.hpp"
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <sys/wait.h>
#include <signal.h>
#include <iostream>
#include <cstring>
#include <vector>

const int BUFFER_SIZE = 4096;

void sigchld_handler(int s)
{
    (void)s;
}

Server::Server(int p) : port(p) {}

void Server::start()
{
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 100) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, 0) == -1)
    {
        perror("sigaction");
        exit(1);
    }

    signal(SIGPIPE, SIG_IGN);

    std::cout << "Server listening on port " << port << std::endl;

    while (true)
    {
        int status;
        while (waitpid(-1, &status, WNOHANG) > 0)
        {
            rate_limiter.decrement_connection();
        }

        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);

        if (client_fd < 0)
        {
            if (errno == EINTR)
                continue;
            perror("accept");
            continue;
        }

        if (!rate_limiter.increment_connection(max_connections))
        {
            std::cerr << "Max connections reached, rejecting." << std::endl;
            std::string body = "Server Busy";
            std::string resp = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: " + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
            send(client_fd, resp.c_str(), resp.size(), 0);
            close(client_fd);
            continue;
        }

        pid_t pid = fork();
        if (pid < 0)
        {
            perror("fork");
            rate_limiter.decrement_connection();
            close(client_fd);
        }
        else if (pid == 0)
        {
            close(server_fd);
            handle_client(client_fd, client_addr);
            close(client_fd);
            exit(0);
        }
        else
        {
            close(client_fd);
        }
    }
}

void Server::handle_client(int client_fd, struct sockaddr_in client_addr)
{
    uint32_t ip = ntohl(client_addr.sin_addr.s_addr);

    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

    std::vector<char> buffer(BUFFER_SIZE);
    std::string request_buffer;

    const size_t MAX_HEADER_SIZE = 8192;

    while (true)
    {
        if (!rate_limiter.allow_request(ip))
        {
            send_response(client_fd, 429, "Too Many Requests");
            break;
        }

        bool headers_complete = false;
        size_t header_end = std::string::npos;

        while (!headers_complete)
        {
            if (request_buffer.size() > MAX_HEADER_SIZE)
            {
                send_response(client_fd, 431, "Request Header Fields Too Large");
                return;
            }

            header_end = request_buffer.find("\r\n\r\n");
            if (header_end != std::string::npos)
            {
                headers_complete = true;
                break;
            }

            ssize_t bytes_read = recv(client_fd, buffer.data(), BUFFER_SIZE, 0);
            if (bytes_read <= 0)
            {
                return;
            }
            request_buffer.append(buffer.data(), bytes_read);
        }

        std::string header_str = request_buffer.substr(0, header_end + 4);
        HttpRequest req = parse_request(header_str);

        if (req.path.find('\0') != std::string::npos)
        {
            send_response(client_fd, 400, "Bad Request");
            return;
        }

        std::string body;
        if (req.content_length > 0)
        {
            size_t body_start = header_end + 4;

            while (request_buffer.size() < body_start + req.content_length)
            {
                if (request_buffer.size() > body_start + req.content_length + MAX_HEADER_SIZE)
                {
                    send_response(client_fd, 413, "Content Too Large");
                    return;
                }

                ssize_t r = recv(client_fd, buffer.data(), BUFFER_SIZE, 0);
                if (r <= 0)
                {
                    return;
                }
                request_buffer.append(buffer.data(), r);
            }
            body = request_buffer.substr(body_start, req.content_length);
        }
        req.body = body;

        if (req.path.empty())
        {
            send_response(client_fd, 400, "Bad Request", "Missing 'path' parameter");
        }
        else
        {
            if (req.method == "GET")
            {
                process_get(client_fd, req.path, req.offset, req.size, req.has_size, req.has_offset);
            }
            else if (req.method == "PUT")
            {
                process_put(client_fd, req.path, req.offset, req.body);
            }
            else
            {
                send_response(client_fd, 405, "Method Not Allowed");
            }
        }

        size_t total_req_size = header_end + 4 + req.content_length;
        if (request_buffer.size() > total_req_size)
        {
            request_buffer = request_buffer.substr(total_req_size);
        }
        else
        {
            request_buffer.clear();
        }

        if (!req.keep_alive)
        {
            break;
        }
    }
}

void Server::send_response(int client_fd, int status, const std::string &msg, const std::string &body)
{
    std::string response = "HTTP/1.1 " + std::to_string(status) + " " + msg + "\r\n";
    response += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    response += "Connection: keep-alive\r\n";
    response += "\r\n";
    response += body;
    send(client_fd, response.c_str(), response.size(), 0);
}

void Server::process_get(int client_fd, const std::string &path, size_t offset, size_t size, bool has_size, bool has_offset)
{
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0)
    {
        send_response(client_fd, 404, "Not Found", "File not found");
        return;
    }

    struct stat st;
    if (fstat(fd, &st) < 0)
    {
        close(fd);
        send_response(client_fd, 500, "Internal Server Error");
        return;
    }

    size_t file_size = st.st_size;
    size_t start = has_offset ? offset : 0;

    if (file_size > 0)
    {
        if (start >= file_size)
        {
            close(fd);
            send_response(client_fd, 416, "Range Not Satisfiable");
            return;
        }

        size_t count = has_size ? size : (file_size - start);
        if (start + count > file_size)
            count = file_size - start;

        std::string header = "HTTP/1.1 200 OK\r\n";
        header += "Content-Length: " + std::to_string(count) + "\r\n";
        header += "Connection: keep-alive\r\n";
        header += "\r\n";
        send(client_fd, header.c_str(), header.size(), 0);

        off_t off = start;
        sendfile(client_fd, fd, &off, count);
        close(fd);
    }
    else
    {
        if (start > 0)
        {
            if (lseek(fd, start, SEEK_SET) == (off_t)-1)
            {
                close(fd);
                send_response(client_fd, 400, "Bad Request", "Seek failed");
                return;
            }
        }

        std::string content;
        std::vector<char> buffer(BUFFER_SIZE);
        size_t max_read = has_size ? size : 16 * 1024 * 1024;
        size_t total_read = 0;

        while (total_read < max_read)
        {
            size_t to_read = BUFFER_SIZE;
            if (total_read + to_read > max_read)
            {
                to_read = max_read - total_read;
            }
            if (to_read == 0)
                break;

            ssize_t r = read(fd, buffer.data(), to_read);
            if (r <= 0)
                break;

            content.append(buffer.data(), r);
            total_read += r;
        }
        close(fd);

        std::string header = "HTTP/1.1 200 OK\r\n";
        header += "Content-Length: " + std::to_string(content.size()) + "\r\n";
        header += "Connection: keep-alive\r\n";
        header += "\r\n";

        send(client_fd, header.c_str(), header.size(), 0);
        send(client_fd, content.c_str(), content.size(), 0);
    }
}

void Server::process_put(int client_fd, const std::string &path, size_t offset, const std::string &content)
{
    int fd = open(path.c_str(), O_WRONLY | O_CREAT, 0644);
    if (fd < 0)
    {
        send_response(client_fd, 500, "Internal Server Error", "Could not open file");
        return;
    }

    if (lseek(fd, offset, SEEK_SET) == (off_t)-1)
    {
        close(fd);
        send_response(client_fd, 400, "Bad Request", "Invalid offset");
        return;
    }

    ssize_t written = write(fd, content.c_str(), content.size());
    close(fd);

    if (written < 0)
    {
        send_response(client_fd, 500, "Internal Server Error");
    }
    else
    {
        send_response(client_fd, 204, "No Content");
    }
}
