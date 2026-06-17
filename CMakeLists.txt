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
    ${CMAKE_SOURCE_DIR}/crypto
    ${CMAKE_SOURCE_DIR}/server
    ${CMAKE_SOURCE_DIR}/client
    ${SQLITE3_INCLUDE_DIRS}
)

file(GLOB_RECURSE SERVER_SOURCES "server/*.cpp")
file(GLOB_RECURSE CLIENT_SOURCES "client/*.cpp")
file(GLOB_RECURSE PROTOCOL_SOURCES "server/protocol/*.cpp")
file(GLOB_RECURSE CRYPTO_SOURCES "crypto/*.cpp")

if(SERVER_SOURCES AND PROTOCOL_SOURCES)
    list(REMOVE_ITEM SERVER_SOURCES ${PROTOCOL_SOURCES})
endif()

list(REMOVE_DUPLICATES SERVER_SOURCES)
list(REMOVE_DUPLICATES CLIENT_SOURCES)
list(REMOVE_DUPLICATES PROTOCOL_SOURCES)
list(REMOVE_DUPLICATES CRYPTO_SOURCES)

add_executable(vcs_server ${SERVER_SOURCES} ${PROTOCOL_SOURCES} ${CRYPTO_SOURCES})
target_include_directories(vcs_server PRIVATE
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/crypto
    ${CMAKE_SOURCE_DIR}/server
    ${SQLITE3_INCLUDE_DIRS}
)
target_link_libraries(vcs_server
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    ${SQLITE3_LIBRARIES}
)

add_executable(vcs_client ${CLIENT_SOURCES} ${PROTOCOL_SOURCES} ${CRYPTO_SOURCES})
target_include_directories(vcs_client PRIVATE
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/crypto
    ${CMAKE_SOURCE_DIR}/client
    ${SQLITE3_INCLUDE_DIRS}
)
target_link_libraries(vcs_client
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    ${SQLITE3_LIBRARIES}
)

enable_testing()

list(FILTER CLIENT_SOURCES EXCLUDE REGEX ".*main\\.cpp$")
list(FILTER SERVER_SOURCES EXCLUDE REGEX ".*main\\.cpp$")
add_executable(test_crypto tests/test_crypto.cpp ${CRYPTO_SOURCES})
target_link_libraries(test_crypto OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
add_test(NAME test_crypto COMMAND test_crypto)


add_executable(test_auth tests/test_auth.cpp ${SERVER_SOURCES} ${PROTOCOL_SOURCES} ${CRYPTO_SOURCES})
target_include_directories(test_auth PRIVATE ${CMAKE_SOURCE_DIR}/server ${SQLITE3_INCLUDE_DIRS})
target_link_libraries(test_auth OpenSSL::SSL OpenSSL::Crypto Threads::Threads ${SQLITE3_LIBRARIES})
add_test(NAME test_auth COMMAND test_auth)

add_executable(test_protocol tests/test_protocol.cpp ${PROTOCOL_SOURCES} ${CRYPTO_SOURCES})
target_link_libraries(test_protocol OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
add_test(NAME test_protocol COMMAND test_protocol)

add_executable(test_ratelimit tests/test_ratelimit.cpp ${SERVER_SOURCES} ${PROTOCOL_SOURCES} ${CRYPTO_SOURCES})
target_include_directories(test_ratelimit PRIVATE ${CMAKE_SOURCE_DIR}/server ${SQLITE3_INCLUDE_DIRS})
target_link_libraries(test_ratelimit OpenSSL::SSL OpenSSL::Crypto Threads::Threads ${SQLITE3_LIBRARIES})
add_test(NAME test_ratelimit COMMAND test_ratelimit)

add_executable(benchmark_load tests/benchmark_load.cpp ${CLIENT_SOURCES} ${PROTOCOL_SOURCES} ${CRYPTO_SOURCES})
target_include_directories(benchmark_load PRIVATE ${CMAKE_SOURCE_DIR}/client ${CMAKE_SOURCE_DIR}/common ${CMAKE_SOURCE_DIR}/server ${SQLITE3_INCLUDE_DIRS})
target_link_libraries(benchmark_load OpenSSL::SSL OpenSSL::Crypto Threads::Threads ${SQLITE3_LIBRARIES})
