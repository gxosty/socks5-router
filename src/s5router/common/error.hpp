#pragma once

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>

    #ifndef errno
        #define errno GetLastError()
    #endif

    #define sock_errno WSAGetLastError()
#endif

#ifdef __linux__
    #include <errno.h>
    #include <cstring>

    #define sock_errno errno
#endif

namespace s5r
{
    static inline int get_last_error()
    {
        return errno;
    }

    static inline int get_last_socket_error()
    {
        return sock_errno;
    }
}