#pragma once

#include "common/net.hpp"
#include <vector>
#include <cstdint>

namespace s5r
{
    enum class S5HandshakeStatus
    {
        Ok,
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

    enum class S5CRCommand
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
            if (_type == Type::IPv4Address)
            {
                return sizeof(in_addr) + 1;
            }
            else if (_type == Type::DomainName)
            {
                return 2 + addr_start;
            }
            else if (_type == Type::IPv6Address)
            {
                return sizeof(in6_addr) + 1;
            }

            return 1;
        }
    };

    struct S5ClientGreeting
    {
        char ver:8;
        char nauth:8;
    };

    struct S5ClientConnectionRequest
    {
        char ver:8;
        char cmd:8;
        char reserved:8;
        S5Address address;

        S5CRCommand get_cmd()
        {
            return static_cast<S5CRCommand>(this->cmd);
        }

        char* get_address()
        {
            return address.get_address();
        }

        uint16_t get_port()
        {
            return *(uint16_t*)(((char*)this) + 3 + address.get_size());
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

    class Socks5Handshake
    {
    public:
        Socks5Handshake(int sock) : _sock{sock} {};
        S5HandshakeStatus handshake(in_addr bind_addr, int* out_sock);

    private:
        int _sock;

    private:
        int recv(char buffer[], int buffer_size);
        int send(char buffer[], int buffer_size);

    private:
        bool _verify_version(char version);

        void _choose_auth_method(char method);

        int _create_tcp_socket(
            std::vector<Destination>* destinations,
            in_addr bind_addr
        );
        int _create_udp_socket(
            std::vector<Destination>* destinations,
            in_addr bind_addr
        );

        // returns 0 if success
        int _extract_address(S5ClientConnectionRequest* request, std::vector<Destination>* destinations);

        void _send_request_status(S5ClientConnectionRequest* request, char status);
    };
}