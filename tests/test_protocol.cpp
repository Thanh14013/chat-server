#include "TestMacro.h"
#include "../server/protocol/Builder.h"
#include "../server/protocol/Parser.h"
#include "../common/Protocol.h"
#include "../server/protocol/Packet.h"

void test_builder_parser() {
    auto reconnect_pkt = Builder::makeReconnectRequest("my_token");
    auto parsed_token = Parser::parseReconnectRequest(reconnect_pkt);
    ASSERT_TRUE(parsed_token == "my_token");

    auto connect_pkt = Builder::makeConnectAccept("my_token", "my_room");
    ASSERT_TRUE(connect_pkt.header.msg_type == static_cast<uint8_t>(MessageType::MSG_CONNECT_ACCEPT));

    // Edge case: Bad payload (not json)
    Packet bad_pkt;
    bad_pkt.header.msg_type = static_cast<uint8_t>(MessageType::MSG_CONNECT_REQUEST);
    bad_pkt.payload = {'b', 'a', 'd'};
    auto parsed_bad = Parser::parseReconnectRequest(bad_pkt);
    ASSERT_TRUE(parsed_bad == "");
    
    auto parsed_conn = Parser::parseConnectRequest(bad_pkt);
    ASSERT_TRUE(parsed_conn.nickname == "");
    ASSERT_TRUE(parsed_conn.password == "");

    // Edge case: Empty payload
    Packet empty_pkt;
    empty_pkt.header.msg_type = static_cast<uint8_t>(MessageType::MSG_CONNECT_REQUEST);
    empty_pkt.payload = {};
    auto empty_conn = Parser::parseConnectRequest(empty_pkt);
    ASSERT_TRUE(empty_conn.nickname == "");

    // Edge case: Valid JSON, missing fields
    std::string json_payload = R"({"nickname":"bob"})"; // missing password
    Packet missing_pkt;
    missing_pkt.header.msg_type = static_cast<uint8_t>(MessageType::MSG_CONNECT_REQUEST);
    missing_pkt.payload = std::vector<uint8_t>(json_payload.begin(), json_payload.end());
    auto missing_conn = Parser::parseConnectRequest(missing_pkt);
    ASSERT_TRUE(missing_conn.nickname == "bob");
    ASSERT_TRUE(missing_conn.password == "");
}

void test_crc32() {
    std::vector<uint8_t> data = {'a', 'b', 'c', '1', '2', '3'};
    uint32_t crc1 = computeCRC32(data);
    uint32_t crc2 = computeCRC32(data);
    ASSERT_EQ(crc1, crc2);

    std::vector<uint8_t> data2 = {'a', 'b', 'c', '1', '2', '4'};
    uint32_t crc3 = computeCRC32(data2);
    ASSERT_NEQ(crc1, crc3);

    // Edge case: Empty data
    std::vector<uint8_t> empty;
    uint32_t crc = computeCRC32(empty);
    ASSERT_EQ(0, crc); // Or whatever initial CRC value is, usually 0
}

int main() {
    RUN_TEST(test_builder_parser);
    RUN_TEST(test_crc32);
    return test::PrintTestResults("Protocol Module");
}
