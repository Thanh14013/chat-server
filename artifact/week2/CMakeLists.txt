cmake_minimum_required(VERSION 3.15)
project(VCSSecureChat VERSION 2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Compile flags ──────────────────────────────────────────────────────────────
add_compile_options(
    -Wall -Wextra -Wpedantic
    -O2
    -fstack-protector-strong          # stack smashing protection
    -D_FORTIFY_SOURCE=2               # buffer overflow detection
)

# ── Dependencies ───────────────────────────────────────────────────────────────
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# SQLite3 — use system package or bundled amalgamation
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(SQLITE3 sqlite3)
endif()
if(NOT SQLITE3_FOUND)
    # Fallback: expect sqlite3.h and libsqlite3 in standard paths
    find_library(SQLITE3_LIBRARIES NAMES sqlite3)
    find_path(SQLITE3_INCLUDE_DIRS NAMES sqlite3.h)
endif()

# nlohmann/json — header-only; expect it in the system or use FetchContent
find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
    include(FetchContent)
    FetchContent_Declare(json
        URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp
        DOWNLOAD_NO_EXTRACT TRUE
        DOWNLOAD_DIR ${CMAKE_BINARY_DIR}/include/nlohmann
    )
    FetchContent_MakeAvailable(json)
    set(NLOHMANN_INCLUDE_DIR ${CMAKE_BINARY_DIR}/include)
else()
    set(NLOHMANN_INCLUDE_DIR "")
endif()

# ── Shared include directories ─────────────────────────────────────────────────
set(COMMON_INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/crypto
    ${OPENSSL_INCLUDE_DIR}
    ${SQLITE3_INCLUDE_DIRS}
    ${NLOHMANN_INCLUDE_DIR}
)

# ══════════════════════════════════════════════════════════════════════════════
# crypto/ library — Week 2 additions
# ══════════════════════════════════════════════════════════════════════════════
add_library(vcs_crypto STATIC
    crypto/random.cpp
    crypto/aes.cpp
    crypto/rsa.cpp
    crypto/hmac.cpp
    crypto/sha256.cpp
)
target_include_directories(vcs_crypto PUBLIC ${COMMON_INCLUDE_DIRS})
target_link_libraries(vcs_crypto PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

# ══════════════════════════════════════════════════════════════════════════════
# vcs_server target
# ══════════════════════════════════════════════════════════════════════════════
add_executable(vcs_server
    # Week 1 sources (unchanged — listed for completeness)
    server/main.cpp
    server/core/TcpServer.cpp
    server/core/ThreadPool.cpp
    server/core/ClientSession.cpp
    server/core/EventLoop.cpp
    server/protocol/Packet.cpp
    server/protocol/Parser.cpp
    server/protocol/Builder.cpp
    server/utils/Logger.cpp
    server/utils/Config.cpp
    server/utils/Database.cpp

    # ── Week 2 additions ──────────────────────────────────────────────────────
    server/security/CryptoEngine.cpp
    server/security/KeyExchange.cpp
    server/security/AuthManager.cpp
    server/security/SessionToken.cpp
)
target_include_directories(vcs_server PRIVATE ${COMMON_INCLUDE_DIRS})
target_link_libraries(vcs_server PRIVATE
    vcs_crypto
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    ${SQLITE3_LIBRARIES}
)

# ══════════════════════════════════════════════════════════════════════════════
# vcs_client target
# ══════════════════════════════════════════════════════════════════════════════
add_executable(vcs_client
    # Week 1 sources (unchanged)
    client/main.cpp
    client/core/TcpClient.cpp
    client/core/MessageQueue.cpp
    client/core/ConnectionManager.cpp
    client/commands/CommandParser.cpp
    client/commands/CommandHandler.cpp

    # ── Week 2 additions ──────────────────────────────────────────────────────
    client/security/ClientCrypto.cpp
    client/security/CertVerifier.cpp
)
target_include_directories(vcs_client PRIVATE ${COMMON_INCLUDE_DIRS})
target_link_libraries(vcs_client PRIVATE
    vcs_crypto
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

# ══════════════════════════════════════════════════════════════════════════════
# Tests
# ══════════════════════════════════════════════════════════════════════════════
enable_testing()

if(EXISTS "${CMAKE_SOURCE_DIR}/tests/test_crypto.cpp")
    add_executable(test_crypto tests/test_crypto.cpp)
    target_include_directories(test_crypto PRIVATE ${COMMON_INCLUDE_DIRS})
    target_link_libraries(test_crypto PRIVATE vcs_crypto)
    add_test(NAME CryptoTests COMMAND test_crypto)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/tests/test_auth.cpp")
    add_executable(test_auth tests/test_auth.cpp
        server/security/AuthManager.cpp
        server/security/SessionToken.cpp
        server/utils/Database.cpp)
    target_include_directories(test_auth PRIVATE ${COMMON_INCLUDE_DIRS})
    target_link_libraries(test_auth PRIVATE vcs_crypto ${SQLITE3_LIBRARIES})
    add_test(NAME AuthTests COMMAND test_auth)
endif()

# ══════════════════════════════════════════════════════════════════════════════
# Install
# ══════════════════════════════════════════════════════════════════════════════
install(TARGETS vcs_server vcs_client DESTINATION bin)
install(FILES server_config.json DESTINATION etc/vcs_chat OPTIONAL)
