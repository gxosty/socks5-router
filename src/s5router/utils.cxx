#include "utils.hpp"
#include <ws2tcpip.h>

namespace s5r
{
    void get_netifaces(std::vector<NetworkInterface>* netifaces)
    {
        PIP_ADAPTER_ADDRESSES pAdapters = NULL;
        ULONG outBufLen = 0;
        ULONG flags = GAA_FLAG_SKIP_MULTICAST;

        // Get the size of the buffer needed
        GetAdaptersAddresses(AF_INET, flags, NULL, NULL, &outBufLen);

        pAdapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(malloc(outBufLen));
        if (pAdapters == NULL) {
            free(pAdapters);
        }

        // Get the adapter addresses
        if (GetAdaptersAddresses(AF_INET, flags, NULL, pAdapters, &outBufLen) == ERROR_SUCCESS) {
            PIP_ADAPTER_ADDRESSES pAdapter = pAdapters;
            while (pAdapter) {
                NetworkInterface& netiface = netifaces->emplace_back(NetworkInterface());
                netiface.name = std::string(pAdapter->AdapterName);

                PIP_ADAPTER_UNICAST_ADDRESS_LH pAddr = pAdapter->FirstUnicastAddress;
                while (pAddr) {
                    if (pAddr->Address.lpSockaddr->sa_family == AF_INET) {
                        netiface.addrs.push_back(((sockaddr_in*)pAddr->Address.lpSockaddr)->sin_addr);
                    }
                    pAddr = pAddr->Next;
                }

                // Check if the interface is up and has a valid IP address
                if (pAdapter->OperStatus != IfOperStatusUp || pAdapter->FirstUnicastAddress == NULL) {
                    netiface.is_running = false;
                } else {
                    netiface.is_running = true;
                }

                // Check if the interface has the "Primary Interface" flag
                DWORD flags = pAdapter->IfType;
                netiface.is_primary = (flags & IF_TYPE_ETHERNET_CSMACD) != 0 && (flags & IF_TYPE_IEEE80211) != 0;

                pAdapter = pAdapter->Next;
            }
        }

        free(pAdapters);
    }

    std::vector<in_addr> get_netiface_ips()
    {
        std::vector<NetworkInterface> netifaces;
        get_netifaces(&netifaces);

        if (netifaces.empty()) return {};

        std::vector<in_addr> addrs;

        for (auto netiface : netifaces)
        {
            for (auto addr : netiface.addrs)
            {
                addrs.push_back(addr);
            }
        }

        return addrs;
    }

    int resolve_dns(const char *domain_name, struct in_addr *ip_addrs, int max_addrs) {
        struct addrinfo hints, *result;
        int i, num_addrs = 0;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET; // IPv4 only

        int status = getaddrinfo(domain_name, NULL, &hints, &result);
        if (status != 0) {
            return -1;
        }

        for (struct addrinfo *rp = result; rp != NULL && num_addrs < max_addrs; rp = rp->ai_next) {
            if (rp->ai_family == AF_INET) {
                struct sockaddr_in *addr = (struct sockaddr_in *)rp->ai_addr;
                memcpy(&ip_addrs[num_addrs], &addr->sin_addr, sizeof(struct in_addr));
                num_addrs++;
            }
        }

        freeaddrinfo(result);
        return num_addrs;
    }
}