#pragma once

#include "common/net.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace s5r
{
    struct NetworkInterface
    {
        std::string name = "";
        std::vector<in_addr> addrs = {};
        bool is_running = false;
        bool is_primary = false;
    };

    void get_netifaces(std::vector<NetworkInterface>* netifaces);
    int resolve_dns(const char *domain_name, struct in_addr *ip_addrs, int max_addrs);
    int get_socket_addr(int sock, sockaddr_in* addr);
}