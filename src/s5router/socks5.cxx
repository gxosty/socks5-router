#include "socks5.hpp"
#include "utils.hpp"
#include "common/poll.hpp"
#include "common/error.hpp"

#include <cstdlib>
#include <unistd.h>

#ifdef _WIN32
    #include <ws2tcpip.h>
#endif

#include <iostream>

namespace s5r
{
    Socks5Proxy::~Socks5Proxy()
    {
        ::shutdown(_sock, SD_BOTH);
        ::close(_sock);
    }

    void Socks5Proxy::serve()
    {
        int rt_sock = 0;
        int udp_sock = 0;
        S5Command command;

        auto status = this->_handshake(&rt_sock, &command, &udp_sock);
        if ((status != S5HandshakeStatus::Ok)
            && (status != S5HandshakeStatus::OkUDPAssociationRequired))
        {
            std::cerr << "SOCKS5 handshake error. Code: "
                    << get_last_socket_error()
#ifdef _WIN32
                    << " (Last Error: "
                    << get_last_error()
                    << ")"
#endif
                    << std::endl;
            if (rt_sock)
            {
                ::shutdown(rt_sock, SD_BOTH);
                ::close(rt_sock);
            }

            delete this;
            return;
        }

        {
            sockaddr_in server_address;

            get_socket_addr(rt_sock, &server_address);

            std::string client_ip = inet_ntoa(_cl_addr.sin_addr);
            std::string server_ip = inet_ntoa(server_address.sin_addr);

            std::cout
                << client_ip
                << ":" << ntohs(_cl_addr.sin_port)
                << " -> "
                << server_ip
                << ":" << ntohs(server_address.sin_port)
                << " | ";
        }

        if (command == S5Command::TCPStream)
        {
            std::cout << "TCP loop" << std::endl;
            _tcp_loop(rt_sock);
            std::cout << inet_ntoa(_cl_addr.sin_addr) << ":" << ntohs(_cl_addr.sin_port) << " TCP loop closed" << std::endl;
        }
        else if (command == S5Command::UDPPort)
        {
            std::cout << "UDP loop" << std::endl;
            _udp_loop(rt_sock, udp_sock);
            std::cout << inet_ntoa(_cl_addr.sin_addr) << ":" << ntohs(_cl_addr.sin_port) <<  " UDP loop closed" << std::endl;
        }

        delete this;
    }

    void Socks5Proxy::_tcp_loop(int rt_sock)
    {
        pollfd fds[2];

        fds[0].fd = _sock;
        fds[0].events = POLLIN;
        fds[0].revents = 0;

        fds[1].fd = rt_sock;
        fds[1].events = POLLIN;
        fds[1].revents = 0;

        char buffer[4096];
        int buffer_size = 4096;

        while (true)
        {
            int poll_result = poll(fds, 2, 10000);

            if (poll_result == -1)
            {
                std::cerr << "Client poll error" << std::endl;
                break;
            }
            else if (poll_result == 0)
            {
                // time out
            }
            else
            {
                // client
                if (fds[0].revents & POLLIN)
                {
                    buffer_size = ::recv(_sock, buffer, 4096, 0);

                    if (buffer_size == -1)
                    {
                        std::cerr << "Client socket recv == -1" << std::endl;
                        break;
                    }

                    // std::cout << "TCP -> " << buffer_size << std::endl;

                    ::send(
                        rt_sock,
                        (char*)buffer,
                        buffer_size,
                        0
                    );

                    fds[0].revents = 0;
                }
                else if (fds[0].revents & POLLHUP)
                {
                    break;
                }
                else if (fds[0].revents & (POLLERR | POLLNVAL))
                {
                    std::cerr << "Client socket error" << std::endl;
                    break;
                }

                // route/server
                if (fds[1].revents & POLLIN)
                {
                    buffer_size = ::recv(
                        rt_sock,
                        (char*)buffer,
                        4096,
                        0
                    );

                    if (buffer_size == -1)
                    {
                        std::cerr << "Route socket recv == -1" << std::endl;
                        break;
                    }

                    // std::cout << "TCP <- " << buffer_size << std::endl;

                    ::send(_sock, buffer, buffer_size, 0);

                    fds[1].revents = 0;
                }
                else if (fds[1].revents & POLLHUP)
                {
                    break;
                }
                else if (fds[1].revents & (POLLERR | POLLNVAL))
                {
                    std::cerr << "Route socket error" << std::endl;
                    break;
                }
            }
        }

        ::shutdown(rt_sock, SD_BOTH);
        ::close(rt_sock);
    }

    void Socks5Proxy::_udp_loop(int rt_sock, int udp_sock)
    {
        pollfd fds[3];

        fds[0].fd = udp_sock;
        fds[0].events = POLLIN;
        fds[0].revents = 0;

        fds[1].fd = rt_sock;
        fds[1].events = POLLIN;
        fds[1].revents = 0;

        fds[2].fd = _sock;
        fds[2].events = POLLIN;
        fds[2].revents = 0;

        char buffer[4096];
        int buffer_size = 4096;

        S5RequestBody udp_header;
        std::vector<Destination> destinations;

        socklen_t cl_addr_len = sizeof(sockaddr_in);
        sockaddr_in cl_addr;
        cl_addr.sin_addr.s_addr = 0;
        cl_addr.sin_port = 0;

        socklen_t sv_addr_len = sizeof(sockaddr_in);
        sockaddr_in sv_addr;
        sv_addr.sin_family = AF_INET;
        sv_addr.sin_addr.s_addr = 0;
        sv_addr.sin_port = 0;

        while (true)
        {
            int poll_result = poll(fds, 3, 10000);

            if (poll_result == -1)
            {
                std::cerr << "Client poll error" << std::endl;
                break;
            }
            else if (poll_result == 0)
            {
                // time out
            }
            else
            {
                // bound client udp
                if (fds[0].revents & POLLIN)
                {
                    buffer_size = ::recvfrom(udp_sock, buffer, 4096, 0,
                        (sockaddr*)&cl_addr, &cl_addr_len);
                    int offset = 0;

                    S5RequestBody* request = reinterpret_cast<S5RequestBody*>(buffer);

                    _extract_address(request, &destinations);

                    memcpy((char*)&udp_header, buffer, request->get_size());
                    udp_header.frag = 0;

                    offset = udp_header.get_size();
                    // std::cout << "Request size: " << offset << std::endl;

                    if (buffer_size == -1)
                    {
                        std::cerr << "Client socket recv == -1" << std::endl;
                        break;
                    }

                    std::cout << "UDP -> " << buffer_size << std::endl;

                    sv_addr.sin_addr = destinations[0].address;
                    sv_addr.sin_port = destinations[0].port;

                    ::sendto(
                        rt_sock,
                        (char*)buffer + offset,
                        buffer_size - offset,
                        0,
                        (sockaddr*)&sv_addr,
                        sv_addr_len
                    );

                    fds[0].revents = 0;
                }
                else if (fds[0].revents & POLLHUP)
                {
                    std::cout << "UDP POLLHUP" << std::endl;
                    break;
                }
                else if (fds[0].revents & (POLLERR | POLLNVAL))
                {
                    std::cerr << "Client socket error" << std::endl;
                    break;
                }

                // route/server
                if (fds[1].revents & POLLIN)
                {
                    int offset = udp_header.get_size();
                    // std::cout << "2Request size: " << offset << std::endl;
                    memcpy(buffer, (char*)&udp_header, offset);

                    buffer_size = ::recvfrom(
                        rt_sock,
                        (char*)buffer + offset,
                        4096 - offset,
                        0,
                        (sockaddr*)&sv_addr,
                        &sv_addr_len
                    ) + offset;

                    if (buffer_size == -1)
                    {
                        std::cerr << "Route socket recv == -1" << std::endl;
                        break;
                    }

                    S5RequestBody* request = reinterpret_cast<S5RequestBody*>(buffer);
                    request->address.type = static_cast<char>(S5Address::Type::IPv4Address);
                    in_addr* udp_addr = reinterpret_cast<in_addr*>(request->address.get_address());
                    *udp_addr = sv_addr.sin_addr;
                    *request->get_port_ptr() = sv_addr.sin_port;

                    std::cout << "UDP <- " << buffer_size << std::endl;

                    ::sendto(udp_sock, buffer, buffer_size, 0,
                        (sockaddr*)&cl_addr, cl_addr_len);

                    fds[1].revents = 0;
                }
                else if (fds[1].revents & POLLHUP)
                {
                    std::cout << "UDP2 POLLHUP" << std::endl;
                    break;
                }
                else if (fds[1].revents & (POLLERR | POLLNVAL))
                {
                    std::cerr << "Route socket error" << std::endl;
                    break;
                }

                if (fds[2].revents & POLLHUP)
                {
                    break;
                }
                else if (fds[2].revents & (POLLERR | POLLNVAL))
                {
                    std::cerr << "UDP TCP (POLLERR | POLLNVAL)" << std::endl;
                    break;
                }
            }
        }

        ::close(rt_sock);
        ::close(udp_sock);
    }

    S5HandshakeStatus Socks5Proxy::_handshake(int* out_sock, S5Command* command, int* out_udp_sock)
    {
        if (!out_sock)
            return S5HandshakeStatus::UnknownError;

        *out_sock = 0;

        static constexpr int BUFFER_SIZE = 1024;
        char buffer[BUFFER_SIZE];
        int buffer_size = 0;

        buffer_size = this->recv(buffer, BUFFER_SIZE);
        if (buffer_size == -1)
        {
            std::cerr << "[1] buffer_size -1" << std::endl;
            return S5HandshakeStatus::UnknownError;
        }

        S5ClientGreeting* greeting = (S5ClientGreeting*)buffer;

        if (!_verify_version(greeting->ver))
        {
            std::cerr << "[2] version mismatch" << std::endl;
            _choose_auth_method(0xFF);
            return S5HandshakeStatus::InvalidVersion;
        }

        char* auths = (char*)(greeting + 1);
        int cauth = 0xFF;
        for (int i = 0; i < greeting->nauth; i++)
        {
            if (auths[i] == 0)
            {
                cauth = 0;
                break;
            }
        }

        _choose_auth_method(cauth);

        buffer_size = this->recv(buffer, BUFFER_SIZE);
        if (buffer_size == -1)
        {
            std::cerr << "[3] buffer_size -1" << std::endl;
            return S5HandshakeStatus::UnknownError;
        }

        S5RequestBody* connection_request = (S5RequestBody*)buffer;

        std::vector<Destination> destinations;

        if (_extract_address(connection_request, &destinations))
        {
            // TODO: Handle errors
            std::cerr << "[4] extract address -1" << std::endl;
            _send_request_status(connection_request, 0x01);
            return S5HandshakeStatus::GeneralFailure;
        }

        if (command)
            *command = connection_request->get_cmd();

        switch (connection_request->get_cmd())
        {
        case S5Command::TCPStream:
            *out_sock = _create_tcp_socket(&destinations);

            if (*out_sock == -1)
            {
                // TODO: Handle errors (with errno)
                std::cerr << "[5] TCP socket creation failed" << std::endl;
                _send_request_status(connection_request, 0x01);
                return S5HandshakeStatus::GeneralFailure;
            }

            _send_request_status(connection_request, 0x0);
            break;
        case S5Command::TCPPort:
            std::cerr << "[6] TCP port binding failed" << std::endl;
            _send_request_status(connection_request, 0x07);
            return S5HandshakeStatus::UnsupportedCommand;
        case S5Command::UDPPort:
            *out_sock = _create_udp_socket(&destinations);

            if (*out_sock == -1)
            {
                // TODO: Handle errors (with errno)
                std::cerr << "[7] UDP port binding failed" << std::endl;
                _send_request_status(connection_request, 0x01);
                return S5HandshakeStatus::GeneralFailure;
            }

            sockaddr_in bind_addr;
            if (get_socket_addr(_sock, &bind_addr) == -1)
            {
                std::cerr << "[8] UDP get_socket_addr == -1" << std::endl;
                _send_request_status(connection_request, 0x01);
                return S5HandshakeStatus::GeneralFailure;
            }

            *out_udp_sock = socket(AF_INET, SOCK_DGRAM, 0);

            if (*out_udp_sock == -1)
            {
                std::cerr << "out_udp_sock == -1" << std::endl;
                _send_request_status(connection_request, 0x01);
                return S5HandshakeStatus::GeneralFailure;
            }

            bind_addr.sin_port = 0;

            ::bind(*out_udp_sock, (sockaddr*)&bind_addr, sizeof(sockaddr_in));
            // ::connect(*out_udp_sock, (sockaddr*)&_cl_addr, sizeof(sockaddr_in));

            if (*out_udp_sock == -1)
            {
                // TODO: Handle errors (with errno)
                std::cerr << "[9] UDP port binding failed" << std::endl;
                _send_request_status(connection_request, 0x01);
                return S5HandshakeStatus::GeneralFailure;
            }

            if (get_socket_addr(*out_udp_sock, &bind_addr) == -1)
            {
                std::cerr << "[10] UDP get_socket_addr == -1" << std::endl;
                _send_request_status(connection_request, 0x01);
                return S5HandshakeStatus::GeneralFailure;
            }

            connection_request->address.type = static_cast<char>(S5Address::Type::IPv4Address);
            in_addr* udp_addr = reinterpret_cast<in_addr*>(connection_request->address.get_address());
            *udp_addr = bind_addr.sin_addr;
            *connection_request->get_port_ptr() = bind_addr.sin_port;

            _send_request_status(connection_request, 0x0);

            if (destinations[0].address.s_addr == 0)
            {
                return S5HandshakeStatus::OkUDPAssociationRequired;
            }

            break;
        }

        return S5HandshakeStatus::Ok;
    }

    int Socks5Proxy::recv(char buffer[], int buffer_size)
    {
        return ::recv(_sock, buffer, buffer_size, 0);
    }

    int Socks5Proxy::send(char buffer[], int buffer_size)
    {
        return ::send(_sock, buffer, buffer_size, 0);
    }

    bool Socks5Proxy::_verify_version(char version)
    {
        return version == 5;
    }

    void Socks5Proxy::_choose_auth_method(char method)
    {
        char buffer[2] = {5, method};
        this->send(buffer, 2);
    }

    int Socks5Proxy::_create_tcp_socket(std::vector<Destination>* destinations) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);

        if (sock == -1)
        {
            return -1;
        }

        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = 0;
        addr.sin_addr = _route_ip;

        if (::bind(sock, (sockaddr*)&addr, sizeof(sockaddr_in)) == -1)
        {
            ::close(sock);
            return -1;
        }

        for (auto& destination : *destinations) {
            addr.sin_port = destination.port;
            addr.sin_addr = destination.address;

            if (!::connect(sock, (sockaddr*)&addr, sizeof(sockaddr_in)))
            {
                return sock;
            }
        }

        ::close(sock);
        return -1;
    }

    int Socks5Proxy::_create_udp_socket(std::vector<Destination>* destinations) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);

        if (sock == -1)
        {
            return -1;
        }

        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = 0;
        addr.sin_addr = _route_ip;

        if (::bind(sock, (sockaddr*)&addr, sizeof(sockaddr_in)) == -1)
        {
            ::close(sock);
            return -1;
        }

        return sock;
    }

    int Socks5Proxy::_extract_address(S5RequestBody* request, std::vector<Destination>* destinations)
    {
        auto type = request->address.get_type();

        if (type == S5Address::Type::IPv4Address)
        {
            destinations->emplace_back(
                *reinterpret_cast<in_addr*>(request->get_address()),
                request->get_port()
            );
        }
        else if (type == S5Address::Type::DomainName)
        {
            char* addr_start = request->get_address();
            char domain_size = *addr_start;
            char* domain_name = addr_start + 1;
            char cdomain_name[domain_size + 1];
            cdomain_name[domain_size] = 0;
            memcpy(cdomain_name, domain_name, domain_size);
            in_addr addrs[10];
            std::cout << "Resolving: " << cdomain_name << std::endl;
            int count = resolve_dns(cdomain_name, addrs, 10);

            if (count == -1)
            {
                std::cerr << "Coudln't resolve IP address (resolve_dns)" << std::endl;
                return -1;
            }

            for (int i = 0; i < count; i++)
            {
                destinations->emplace_back(
                    addrs[i],
                    request->get_port()
                );
            }
        }
        else
        {
            std::cerr << "IPv6 is not supported" << std::endl;
            return -1;
        }

        return 0;
    }

    void Socks5Proxy::_send_request_status(S5RequestBody* request, char status)
    {
        auto buffer_size = request->get_size();
        char buffer[buffer_size];
        memcpy(buffer, (char*)request, buffer_size);

        ((S5RequestBody*)buffer)->cmd = status;

        this->send(buffer, buffer_size);
    }
}