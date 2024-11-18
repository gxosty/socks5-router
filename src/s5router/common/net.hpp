#ifdef _WIN32
    #include <winsock2.h>
    #include <iphlpapi.h>
#endif

// Linux is not supported yet, but is planned
#ifdef __linux__
    #include <sys/socket.h>
    #include <netinet/in.h>
#endif