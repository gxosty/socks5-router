#include "s5router.hpp"
#include "socks5.hpp"
#include "common/poll.hpp"

#include <iostream> // I know including this is a bad idea but whatever
#include <stdexcept>
#include <thread>
#include <unistd.h>

#ifdef _WIN32
    #include <ws2tcpip.h>
#endif

namespace s5r
{
#ifdef _WIN32
    /**
     * Windows requires WSAStartup function to
     * be called first before using any socket API
     **/

    bool _initialized = false;

    void _initialize()
    {
        if (_initialized) return;

        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            // TODO: Handle errors
            std::cerr << "WSAStartup error" << std::endl;
        }
    }
#endif

    S5Router::S5Router(
        uint16_t server_port,
        in_addr server_ip,
        in_addr route_ip
    ) : _server_port{server_port},
        _server_ip{server_ip},
        _route_ip{route_ip},
        _running{false}
    {
#ifdef _WIN32
        _initialize();
#endif
    }

    bool S5Router::run()
    {
        std::vector<NetworkInterface> netifaces;
        get_netifaces(&netifaces);

        std::vector<int> server_socks;
        in_addr route_ip = _route_ip;

        if (_server_ip.s_addr == 0)
        {
            for (auto& netiface : netifaces)
            {
                if (!netiface.is_running)
                    continue;

                for (auto addr : netiface.addrs)
                {
                    server_socks.push_back(
                        _open_server_socket(addr)
                    );
                }
            }
        }
        else
        {
            NetworkInterface* listen_netiface = _find_interface_by_address(netifaces, _server_ip);

            if (!listen_netiface)
            {
                // throw std::runtime_error(
                //     "No Network Interface/Adapter found with IPv4 address: "
                //     + std::string(inet_ntoa(_server_ip))
                // );
                return false;
            }

            server_socks.push_back(
                _open_server_socket(_server_ip)
            );
        }

        if (server_socks.empty())
        {
            return false;
        }

        if (route_ip.s_addr == 0)
        {
            NetworkInterface* route_netiface = _find_primary_interface(netifaces);

            if (!route_netiface)
            {
                return false;
            }

            route_ip = route_netiface->addrs[0];

            std::cout << "Chosen route: " << inet_ntoa(route_ip) << std::endl;
        }
        else
        {
            NetworkInterface* route_netiface = _find_interface_by_address(netifaces, route_ip);

            if (!route_netiface)
            {
                return false;
            }
        }

        int socks[server_socks.size()];
        for (int i = 0; i < server_socks.size(); i++)
        {
            socks[i] = server_socks[i];
        }

        // Server loop here
        _running = true;
        _server_loop(socks, server_socks.size(), route_ip);

        for (int i = 0; i < server_socks.size(); i++)
        {
            ::close(socks[i]);
        }

        return true;
    }

    void S5Router::stop()
    {
        _running = false;
    }

    bool S5Router::is_running()
    {
        return _running;
    }

    void S5Router::_server_loop(int socks[], int sock_count, in_addr route_ip)
    {
        pollfd fds[sock_count];

        for (int i = 0; i < sock_count; i++)
        {
            fds[i].fd = socks[i];
            fds[i].events = POLLIN;
            fds[i].revents = 0;
        }

        while (_running)
        {
            int poll_result = poll(fds, sock_count, 2000);

            if (poll_result == -1)
            {
                stop();
                return;
            }
            else if (poll_result == 0)
            {
                // time out
            }
            else
            {
                for (int i = 0; i < sock_count; i++)
                {
                    if (fds[i].revents & POLLIN)
                    {
                        int sock = fds[i].fd;

                        sockaddr_in addr;
                        socklen_t addr_len = sizeof(sockaddr_in);
                        int cl_sock = ::accept(sock, (sockaddr*)&addr, &addr_len);

                        if (cl_sock != -1)
                        {
                            Socks5Proxy* proxy = new Socks5Proxy(addr, cl_sock, route_ip);
                            std::thread th([](void* _proxy) -> void {
                                ((Socks5Proxy*)_proxy)->serve();
                            }, (void*)proxy);
                            th.detach();
                        }
                        else
                        {
                            std::cerr << "Couldn't accept socket connection" << std::endl;
                        }

                        fds[i].revents = 0;
                    }
                    else if (fds[i].revents & (POLLHUP | POLLERR | POLLNVAL))
                    {
                        std::cerr << "Socket error when polling" << std::endl;
                        stop();
                        return;
                    }
                }
            }
        }
    }

    int S5Router::_open_server_socket(in_addr address)
    {
        int sock = socket(AF_INET, SOCK_STREAM, 0);

        sockaddr_in sock_addr;
        sock_addr.sin_family = AF_INET;
        sock_addr.sin_port = htons(this->_server_port);
        sock_addr.sin_addr = address;

        if (::bind(sock, (sockaddr*)&sock_addr, sizeof(sockaddr_in)) == -1)
        {
            return 0;
        }

        if (::listen(sock, 4096) == -1)
        {
            return 0;
        }

        return sock;
    }

    NetworkInterface* S5Router::_find_interface_by_address(
        const std::vector<NetworkInterface>& netifaces,
        in_addr addr
    ) {
        for (auto& netiface : netifaces)
        {
            for (auto _addr : netiface.addrs)
            {
                if (_addr.s_addr == addr.s_addr)
                {
                    return const_cast<NetworkInterface*>(&netiface);
                }
            }
        }

        return nullptr;
    }

    NetworkInterface* S5Router::_find_primary_interface(
        const std::vector<NetworkInterface>& netifaces
    ) {
        for (auto& netiface : netifaces)
        {
            if (netiface.is_primary && netiface.is_running)
                return const_cast<NetworkInterface*>(&netiface);
        }

        return nullptr;
    }
}