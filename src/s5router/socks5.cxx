#include "socks5.hpp"
#include "utils.hpp"

#include <cstdlib>
#include <unistd.h>

#ifdef _WIN32
    #include <ws2tcpip.h>
#endif

#include <iostream>

namespace s5r
{
    S5HandshakeStatus Socks5Handshake::handshake(in_addr bind_addr, int* out_sock)
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

        S5ClientConnectionRequest* connection_request = (S5ClientConnectionRequest*)buffer;

        std::vector<Destination> destinations;

        if (_extract_address(connection_request, &destinations))
        {
            // TODO: Handle errors
            std::cerr << "[4] extract address -1" << std::endl;
            _send_request_status(connection_request, 0x01);
            return S5HandshakeStatus::GeneralFailure;
        }

        switch (connection_request->get_cmd())
        {
        case S5CRCommand::TCPStream:
            *out_sock = _create_tcp_socket(&destinations, bind_addr);

            if (*out_sock == -1)
            {
                // TODO: Handle errors (with errno)
                std::cerr << "[5] TCP socket creation failed" << std::endl;
                _send_request_status(connection_request, 0x01);
                return S5HandshakeStatus::GeneralFailure;
            }

            _send_request_status(connection_request, 0x0);
            break;
        case S5CRCommand::TCPPort:
            std::cerr << "[6] TCP port binding failed" << std::endl;
            _send_request_status(connection_request, 0x07);
            return S5HandshakeStatus::UnsupportedCommand;
        case S5CRCommand::UDPPort:
            *out_sock = _create_udp_socket(&destinations, bind_addr);

            if (*out_sock == -1)
            {
                // TODO: Handle errors (with errno)
                std::cerr << "[7] UDP port binding failed" << std::endl;
                _send_request_status(connection_request, 0x01);
                return S5HandshakeStatus::GeneralFailure;
            }

            _send_request_status(connection_request, 0x0);
            break;
        }

        std::cerr << "[8] OK" << std::endl;
        return S5HandshakeStatus::Ok;
    }

    int Socks5Handshake::recv(char buffer[], int buffer_size)
    {
        return ::recv(_sock, buffer, buffer_size, 0);
    }

    int Socks5Handshake::send(char buffer[], int buffer_size)
    {
        return ::send(_sock, buffer, buffer_size, 0);
    }

    bool Socks5Handshake::_verify_version(char version)
    {
        return version == 5;
    }

    void Socks5Handshake::_choose_auth_method(char method)
    {
        char buffer[2] = {5, method};
        this->send(buffer, 2);
    }

    int Socks5Handshake::_create_tcp_socket(
        std::vector<Destination>* destinations,
        in_addr bind_addr
    ) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);

        if (sock == -1)
        {
            return -1;
        }

        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = 0;
        addr.sin_addr = bind_addr;

        if (::bind(sock, (sockaddr*)&addr, sizeof(sockaddr_in)) == -1)
        {
            ::close(sock);
            return -1;
        }

        bool connected = false;

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

    int Socks5Handshake::_create_udp_socket(
        std::vector<Destination>* destinations,
        in_addr bind_addr
    ) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);

        if (sock == -1)
        {
            std::cerr << "UDP create error" << std::endl;
            return -1;
        }

        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = 0;
        addr.sin_addr = bind_addr;

        if (::bind(sock, (sockaddr*)&addr, sizeof(sockaddr_in)) == -1)
        {
            std::cerr << "UDP bind error" << std::endl;
            ::close(sock);
            return -1;
        }

        bool connected = false;

        for (auto& destination : *destinations) {
            addr.sin_port = destination.port;
            addr.sin_addr = destination.address;

            if (!::connect(sock, (sockaddr*)&addr, sizeof(sockaddr_in)))
            {
                return sock;
            }
        }

        std::cerr << "UDP connect error" << std::endl;
        ::close(sock);
        return -1;
    }

    int Socks5Handshake::_extract_address(S5ClientConnectionRequest* request, std::vector<Destination>* destinations)
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

    void Socks5Handshake::_send_request_status(S5ClientConnectionRequest* request, char status)
    {
        auto buffer_size = request->get_size();
        char buffer[buffer_size];
        memcpy(buffer, (char*)request, buffer_size);

        ((S5ClientConnectionRequest*)buffer)->cmd = status;

        this->send(buffer, buffer_size);
    }
}