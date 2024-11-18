cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(SOCKS5Router VERSION 0.1.0 LANGUAGES CXX C)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

option(S5ROUTER_CLI_INTERFACE "Build CLI interface" ON)

add_library(s5r
    src/s5router/s5router.cxx
    src/s5router/socks5.cxx
    src/s5router/utils.cxx
)

if (S5ROUTER_CLI_INTERFACE)
    list(APPEND S5ROUTER_CLI_LIBS
        s5r
    )

    if (WIN32)
        list(APPEND S5ROUTER_CLI_LIBS
            ws2_32
            iphlpapi
        )
    endif()

    add_executable(s5r_cli
        src/cli.cxx
    )

    target_link_libraries(s5r_cli
        ${S5ROUTER_CLI_LIBS}
    )
endif()