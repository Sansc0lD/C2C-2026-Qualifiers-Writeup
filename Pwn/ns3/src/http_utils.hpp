#ifndef HTTP_UTILS_HPP
#define HTTP_UTILS_HPP

#include <string>
#include <map>
#include <sstream>
#include <vector>
#include <iostream>
#include <algorithm>

struct HttpRequest
{
    std::string method;
    std::string path;
    size_t size = 0;
    size_t offset = 0;
    bool has_size = false;
    bool has_offset = false;
    size_t content_length = 0;
    std::string body;
    bool keep_alive = false;
    std::string uri;
};

inline std::string url_decode(const std::string &str)
{
    std::string ret;
    char ch;
    int i, ii;
    for (i = 0; i < (int)str.length(); i++)
    {
        if (str[i] != '%')
        {
            if (str[i] == '+')
                ret += ' ';
            else
                ret += str[i];
        }
        else
        {
            sscanf(str.substr(i + 1, 2).c_str(), "%x", &ii);
            ch = static_cast<char>(ii);
            ret += ch;
            i = i + 2;
        }
    }
    return ret;
}

inline HttpRequest parse_request(const std::string &header_str)
{
    HttpRequest req;
    std::istringstream stream(header_str);
    std::string line;

    if (std::getline(stream, line))
    {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();

        std::istringstream linestream(line);
        std::string method, uri, version;
        linestream >> method >> uri >> version;

        req.method = method;
        req.uri = uri;

        size_t q_pos = uri.find('?');
        if (q_pos != std::string::npos)
        {
            std::string query = uri.substr(q_pos + 1);
            std::istringstream qstream(query);
            std::string segment;
            while (std::getline(qstream, segment, '&'))
            {
                size_t eq_pos = segment.find('=');
                if (eq_pos != std::string::npos)
                {
                    std::string key = segment.substr(0, eq_pos);
                    std::string val = url_decode(segment.substr(eq_pos + 1));

                    if (key == "path")
                        req.path = val;
                    else if (key == "size")
                    {
                        req.size = std::stoul(val);
                        req.has_size = true;
                    }
                    else if (key == "offset")
                    {
                        req.offset = std::stoul(val);
                        req.has_offset = true;
                    }
                }
            }
        }
    }

    while (std::getline(stream, line) && line != "\r")
    {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            break;

        size_t colon = line.find(':');
        if (colon != std::string::npos)
        {
            std::string key = line.substr(0, colon);
            std::string val = line.substr(colon + 1);
            val.erase(0, val.find_first_not_of(" \t"));

            std::transform(key.begin(), key.end(), key.begin(), ::tolower);

            if (key == "content-length")
            {
                req.content_length = std::stoul(val);
            }
            else if (key == "connection")
            {
                std::transform(val.begin(), val.end(), val.begin(), ::tolower);
                if (val.find("keep-alive") != std::string::npos)
                {
                    req.keep_alive = true;
                }
                else if (val.find("close") != std::string::npos)
                {
                    req.keep_alive = false;
                }
            }
        }
    }

    if (req.method.empty())
        req.keep_alive = false;

    return req;
}

#endif
