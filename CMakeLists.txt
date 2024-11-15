cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(SOCKS5Router VERSION 0.1.0 LANGUAGES CXX C)

option(S5ROUTER_CLI_INTERFACE "Build CLI interface" ON)

# add_library(s5r

# )

if (S5ROUTER_CLI_INTERFACE)
    add_executable(s5r_cli
        src/cli.cxx
    )
endif()