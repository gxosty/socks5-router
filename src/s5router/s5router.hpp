#pragma once

#include "common/net.hpp"
#include "utils.hpp"
#include <cstdint>

namespace s5r
{
    class S5Router
    {
    public:
        S5Router(
            // open connection at port
            uint16_t server_port = 7530,

            // listen on all interfaces
            // defaults to 0.0.0.0
            in_addr server_ip = {0},

            // no routing, act like transparent proxy
            // defaults to 0.0.0.0
            in_addr route_ip = {0}
        );

        // runs the server (blocking)
        // returns false if run wasn't successfull
        bool run();

        // stops the server
        void stop();

        // checks if server is currently running
        bool is_running();

    private:
        uint16_t _server_port;
        in_addr _server_ip;
        in_addr _route_ip;

    private:
        bool _running;

    private:
        // Server related
        void _client_loop(int sock, uint32_t u32_route_ip);
        void _server_loop(int socks[], int sock_count, in_addr route_ip);

        int _open_server_socket(in_addr address);

    private:
        // Helpers/Utils
        NetworkInterface* _find_interface_by_address(
            const std::vector<NetworkInterface>& netifaces,
            in_addr addr
        );

        NetworkInterface* _find_primary_interface(
            const std::vector<NetworkInterface>& netifaces
        );

    };
}