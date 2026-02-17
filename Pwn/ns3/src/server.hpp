#ifndef SERVER_HPP
#define SERVER_HPP

#include "shm_rate_limiter.hpp"
#include <netinet/in.h>

class Server
{
private:
    int server_fd;
    int port;
    int max_connections = 100;
    ShmRateLimiter rate_limiter;

    void handle_client(int client_fd, struct sockaddr_in client_addr);
    void process_get(int client_fd, const std::string &path, size_t offset, size_t size, bool has_size, bool has_offset);
    void process_put(int client_fd, const std::string &path, size_t offset, const std::string &content);

    void send_response(int client_fd, int status, const std::string &msg, const std::string &body = "");

public:
    Server(int port);
    void start();
};

#endif
