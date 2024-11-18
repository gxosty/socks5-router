#include <argparse/argparse.hpp>

#include "s5router/common/net.hpp"
#include "s5router/s5router.hpp"
#include "s5router/utils.hpp"

#ifdef _WIN32
    #include <ws2tcpip.h>
#endif

#include <iostream>
#include <signal.h>

#define __S5R_VERSION__ "0.1.0"

// Global variable because simple project
s5r::S5Router* router = nullptr;

struct Params {
    uint16_t server_port;
    in_addr server_ip;
    in_addr route_ip;
};

Params parse_args(int argc, char** argv)
{
    argparse::ArgumentParser parser(argv[0], __S5R_VERSION__);

    parser.add_argument("--port")
        .help("Open SOCKS5 server on port.")
        .default_value(7530)
        .scan<'i', int>()
        .nargs(1);

    parser.add_argument("--listen")
        .help("Listen on IP address (only IPv4 is supported).\n0.0.0.0 will listen to all interfaces")
        .default_value("0.0.0.0")
        .nargs(1);

    parser.add_argument("--route")
        .help("Route traffic to ip address.\n0.0.0.0 will make server act like transparent proxy")
        .default_value("0.0.0.0")
        .nargs(1);

    try {
        parser.parse_args(argc, argv);
    } catch (const std::exception& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << parser;
        exit(1);
    }

    std::string listen_str = parser.get<std::string>("--listen");
    in_addr listen_addr;
    inet_pton(AF_INET, listen_str.c_str(), &listen_addr);

    std::string route_str = parser.get<std::string>("--route");
    in_addr route_addr;
    inet_pton(AF_INET, route_str.c_str(), &route_addr);

    Params params{
        (uint16_t)parser.get<int>("--port"),
        listen_addr,
        route_addr
    };

    return params;
}

void signal_handler(int sig)
{
    if (router)
    {
        std::cout << "Stopping..." << std::endl;
        router->stop();
    }
}

void print_info(const Params& params)
{
    std::cout
        << "Listening connection on "
        << inet_ntoa(params.server_ip)
        << ":"
        << params.server_port
        << std::endl;

    std::cout
        << "Routing traffic to -> "
        << inet_ntoa(params.route_ip)
        << std::endl;
}

int main(int argc, char** argv) {
    Params params = parse_args(argc, argv);

    router = new s5r::S5Router(
        params.server_port,
        params.server_ip,
        params.route_ip
    );

    print_info(params);

    if (signal(SIGINT, signal_handler) == SIG_ERR)
    {
        std::cerr
            << "Warning: settings SIGINT handler was unsuccessfull"
            << std::endl;
    }

    router->run();

    return 0;
}