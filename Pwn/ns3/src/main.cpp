#include "server.hpp"
#include <iostream>

int main(int argc, char *argv[])
{
    int port = 8080;
    if (argc > 1)
    {
        port = std::stoi(argv[1]);
    }

    Server server(port);
    server.start();

    return 0;
}
