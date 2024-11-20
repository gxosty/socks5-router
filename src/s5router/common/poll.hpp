#pragma once

#ifdef _WIN32
    #include <winsock2.h>
    #define poll WSAPoll
#endif

#ifdef __linux__
    #include <poll.h>
#endif