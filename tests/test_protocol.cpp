#include "test_framework.h"
#include "../common/Protocol.h"
#include "../common/Constants.h"
#include "../common/MessageTypes.h"
#include "../common/ErrorCodes.h"
#include "../server/protocol/Packet.h"
#include "../server/protocol/Builder.h"
#include "../server/protocol/Parser.h"
#include <cstring>

TEST(header_size) {
    ASSERT_EQ(sizeof(PacketHeader), (size_t)17);
}

TEST(magic_bytes) {
    Packet p;
    ASSERT_EQ(p.header.magic[0], Constants::MAGIC_BYTE_0);
    ASSERT_EQ(p.header.magic[1], Constants::MAGIC_BYTE_1);
}

TEST(packet_serialize_deserialize) {
    std::string msg = "{\"nickname\":\"Alice\",\"password\":\"\"}";
    std::vector<uint8_t> payload(msg.begin(), msg.end());
    Packet pkt(MessageType::MSG_CONNECT_REQUEST, payload);

    auto bytes = packetToBytes(pkt);
    ASSERT_TRUE(bytes.size() >= sizeof(PacketHeader));

    PacketHeader hdr;
    std::memcpy(&hdr, bytes.data(), sizeof(PacketHeader));
    ASSERT_EQ(hdr.magic[0], Constants::MAGIC_BYTE_0);
    ASSERT_EQ(hdr.magic[1], Constants::MAGIC_BYTE_1);
    ASSERT_EQ(hdr.version,  Constants::PROTOCOL_VERSION);
    ASSERT_EQ(hdr.msg_type, (uint8_t)MessageType::MSG_CONNECT_REQUEST);
    ASSERT_EQ(hdr.payload_length, (uint32_t)payload.size());
}

TEST(crc32_detects_corruption) {
    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    uint32_t crc1 = computeCRC32(data);
    data[0] = 'h';
    uint32_t crc2 = computeCRC32(data);
    ASSERT_NE(crc1, crc2);
}

TEST(crc32_empty_data) {
    std::vector<uint8_t> empty;
    uint32_t crc = computeCRC32(empty);
    ASSERT_EQ(crc, (uint32_t)0x00000000);
}

TEST(builder_system_notify) {
    auto pkt = Builder::makeSystemNotify("Hello World");
    ASSERT_EQ(pkt.header.msg_type, (uint8_t)MessageType::MSG_SYSTEM_NOTIFY);
    ASSERT_TRUE(!pkt.payload.empty());
    std::string body(pkt.payload.begin(), pkt.payload.end());
    ASSERT_TRUE(body.find("Hello World") != std::string::npos);
}

TEST(builder_connect_reject) {
    auto pkt = Builder::makeConnectReject(ErrorCode::ERR_NICKNAME_TAKEN, "taken");
    ASSERT_EQ(pkt.header.msg_type, (uint8_t)MessageType::MSG_CONNECT_REJECT);
}

TEST(builder_ping_pong_empty_payload) {
    auto ping = Builder::makePing();
    auto pong = Builder::makePong();
    ASSERT_TRUE(ping.payload.empty());
    ASSERT_TRUE(pong.payload.empty());
}

TEST(parser_connect_request) {
    std::string json = "{\"nickname\":\"Bob\",\"password\":\"secret\"}";
    std::vector<uint8_t> payload(json.begin(), json.end());
    Packet pkt(MessageType::MSG_CONNECT_REQUEST, payload);

    auto parsed = Parser::parseConnectRequest(pkt);
    ASSERT_EQ(parsed.nickname, std::string("Bob"));
    ASSERT_EQ(parsed.password, std::string("secret"));
}

TEST(parser_chat_send) {
    std::string json = "{\"message\":\"Hello!\",\"room\":\"general\"}";
    std::vector<uint8_t> payload(json.begin(), json.end());
    Packet pkt(MessageType::MSG_CHAT_SEND, payload);

    auto parsed = Parser::parseChatSend(pkt);
    ASSERT_EQ(parsed.message, std::string("Hello!"));
    ASSERT_EQ(parsed.room,    std::string("general"));
}

TEST(parser_malformed_json_safe) {
    std::string bad = "NOT JSON {{{{";
    std::vector<uint8_t> payload(bad.begin(), bad.end());
    Packet pkt(MessageType::MSG_CONNECT_REQUEST, payload);

    auto parsed = Parser::parseConnectRequest(pkt);
    ASSERT_TRUE(parsed.nickname.empty());
}

TEST(packet_sequence_num) {
    Packet p;
    p.header.sequence_num = 42;
    auto bytes = packetToBytes(p);
    PacketHeader hdr;
    std::memcpy(&hdr, bytes.data(), sizeof(PacketHeader));
    ASSERT_EQ(hdr.sequence_num, (uint32_t)42);
}

TEST(packet_large_payload) {
    std::string large(60000, 'A');
    std::vector<uint8_t> payload(large.begin(), large.end());
    Packet pkt(MessageType::MSG_CHAT_SEND, payload);
    auto bytes = packetToBytes(pkt);
    
    PacketHeader hdr;
    std::memcpy(&hdr, bytes.data(), sizeof(PacketHeader));
    ASSERT_EQ(hdr.payload_length, (uint32_t)60000);
}

int main() {
    return run_all_tests("Protocol Tests");
}
