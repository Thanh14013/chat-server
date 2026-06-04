cmake_minimum_required(VERSION 3.15)
project(VCSSecureChat VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O2")

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)

include_directories(
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/server
    ${CMAKE_SOURCE_DIR}/client
    ${SQLITE3_INCLUDE_DIRS}
)

file(GLOB_RECURSE SERVER_SOURCES
    "server/*.cpp"
)

file(GLOB_RECURSE CLIENT_SOURCES
    "client/*.cpp"
)

add_executable(vcs_server ${SERVER_SOURCES})
target_include_directories(vcs_server PRIVATE
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/server
    ${SQLITE3_INCLUDE_DIRS}
)
target_link_libraries(vcs_server
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    ${SQLITE3_LIBRARIES}
)

add_executable(vcs_client ${CLIENT_SOURCES})
target_include_directories(vcs_client PRIVATE
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/client
    ${SQLITE3_INCLUDE_DIRS}
)
target_link_libraries(vcs_client
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    ${SQLITE3_LIBRARIES}
)
