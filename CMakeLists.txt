cmake_minimum_required(VERSION 3.26)
project(elrs_wifi_joystick C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(elrs_wifi_joystick
        elrs-wifi-joystick.c
        mdns.h)

find_package(PkgConfig REQUIRED)
pkg_check_modules(libcurl REQUIRED IMPORTED_TARGET libcurl>=7.17.0)
target_link_libraries(elrs_wifi_joystick PUBLIC PkgConfig::libcurl)
