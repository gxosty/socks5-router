#pragma once

#include "common/net.hpp"
#include <vector>
#include <cstdint>
// #include <iostream>

namespace s5r
{
    enum class S5HandshakeStatus
    {
        Ok,
        OkUDPAssociationRequired,
        UnknownError,
        InvalidVersion,
        UnsupportedAuthMethod,
        AuthenticationFail,
        GeneralFailure,
        ConnectionNotAllowedByRuleset,
        NetworkUnreachable,
        HostUnreachable,
        ConnectionRefusedByDestinationHost,
        TTLExpired,
        UnsupportedCommand,
        UnsupportedAddressType
    };

    enum class S5Command
    {
        TCPStream = 1,
        TCPPort = 2,
        UDPPort = 3
    };

    struct S5Address
    {
        enum class Type
        {
            IPv4Address = 1,
            DomainName = 3,
            IPv6Address = 4
        };

        char type:8;
        char addr_start;

        Type get_type()
        {
            return (Type)(this->type);
        }

        char* get_address()
        {
            return &(this->addr_start);
        }

        size_t get_size() const
        {
            Type _type = static_cast<Type>(type);
            // if (_type == Type::IPv4Address)
            // {
            //     return sizeof(in_addr) + 1;
            // }
            // else if (_type == Type::DomainName)
            // {
            //     return 2 + addr_start;
            // }
            // else if (_type == Type::IPv6Address)
            // {
            //     return sizeof(in6_addr) + 1;
            // }

            switch (_type)
            {
            case Type::IPv4Address:
                return sizeof(in_addr) + 1;
            case Type::DomainName:
                return 2 + addr_start;
            case Type::IPv6Address:
                return sizeof(in6_addr) + 1;
            }

            // std::cout << "S5Address get_size reached the end" << std::endl;

            return 1;
        }
    };

    struct S5ClientGreeting
    {
        char ver:8;
        char nauth:8;
    };

    struct S5RequestBody
    {
        char ver:8;
        char cmd:8;
        char frag:8; // reserved, but can be used as frag
        S5Address address;

        S5Command get_cmd()
        {
            return static_cast<S5Command>(this->cmd);
        }

        char* get_address()
        {
            return address.get_address();
        }

        inline uint16_t* get_port_ptr()
        {
            return (uint16_t*)(((char*)this) + 3 + address.get_size());
        }

        uint16_t get_port()
        {
            return *this->get_port_ptr();
        }

        size_t get_size() const
        {
            return 3 + address.get_size() + 2;
        }
    };

    struct Destination {
        in_addr address;
        uint16_t port;

        Destination(in_addr address, uint16_t port)
            : address{address}, port{port} {}
    };

    class Socks5Proxy
    {
    public:
        Socks5Proxy(const sockaddr_in& cl_addr, int sock, in_addr route_ip)
            : _cl_addr{cl_addr}, _sock{sock}, _route_ip{route_ip} {}

        ~Socks5Proxy();

        void serve();

    private:
        sockaddr_in _cl_addr;
        int _sock;
        in_addr _route_ip;

    private:
        int recv(char buffer[], int buffer_size);
        int send(char buffer[], int buffer_size);

    private:
        void _tcp_loop(int rt_sock);
        void _udp_loop(int rt_sock, int udp_sock);

        S5HandshakeStatus _handshake(int* out_sock, S5Command* command, int* out_udp_sock);

        bool _verify_version(char version);

        void _choose_auth_method(char method);

        int _create_tcp_socket(std::vector<Destination>* destinations);
        int _create_udp_socket(std::vector<Destination>* destinations);

        // returns 0 if success
        int _extract_address(S5RequestBody* request, std::vector<Destination>* destinations);

        void _send_request_status(S5RequestBody* request, char status);
    };
}