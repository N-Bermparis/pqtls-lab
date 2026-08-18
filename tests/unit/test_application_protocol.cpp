#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "pqtls/application_protocol.hpp"
#include "pqtls/error.hpp"

using namespace pqtls;

namespace {

std::span<const std::uint8_t> as_span(const std::vector<std::uint8_t>& v) {
    return std::span<const std::uint8_t>(v.data(), v.size());
}

[[maybe_unused]] std::vector<std::uint8_t> bytes(std::string_view text) {
    return std::vector<std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()),
                                     reinterpret_cast<const std::uint8_t*>(text.data() + text.size()));
}

}  // namespace

// ---------------------------------------------------------------------------
// Frame encoding
// ---------------------------------------------------------------------------
TEST_CASE("encode writes a big-endian length prefix", "[framing]") {
    const auto frame = framing::encode("hello");

    REQUIRE(frame.size() == framing::kHeaderSize + 5);
    // Network byte order, independent of the host's endianness.
    CHECK(frame[0] == 0x00);
    CHECK(frame[1] == 0x00);
    CHECK(frame[2] == 0x00);
    CHECK(frame[3] == 0x05);
    CHECK(std::string(frame.begin() + 4, frame.end()) == "hello");
}

TEST_CASE("encode rejects an empty payload", "[framing]") {
    CHECK_THROWS_AS(framing::encode(""), ProtocolError);
}

TEST_CASE("encode rejects a payload above the configured maximum", "[framing]") {
    const std::string payload(64, 'x');
    CHECK_THROWS_AS(framing::encode(payload, 32), ProtocolError);
    CHECK_NOTHROW(framing::encode(payload, 64));
}

TEST_CASE("encode refuses a maximum above the absolute ceiling", "[framing]") {
    // A typo in a config file must not become a memory-exhaustion primitive.
    CHECK_THROWS_AS(framing::encode("x", framing::kAbsoluteMaxFrameSize + 1), ProtocolError);
}

// ---------------------------------------------------------------------------
// Length decoding
// ---------------------------------------------------------------------------
TEST_CASE("decode_length reads a big-endian length", "[framing]") {
    const std::vector<std::uint8_t> header{0x00, 0x00, 0x01, 0x00};
    CHECK(framing::decode_length(as_span(header)) == 256);
}

TEST_CASE("decode_length rejects a header of the wrong size", "[framing]") {
    const std::vector<std::uint8_t> too_short{0x00, 0x00, 0x01};
    const std::vector<std::uint8_t> too_long{0x00, 0x00, 0x00, 0x01, 0x00};
    CHECK_THROWS_AS(framing::decode_length(as_span(too_short)), ProtocolError);
    CHECK_THROWS_AS(framing::decode_length(as_span(too_long)), ProtocolError);
}

TEST_CASE("decode_length rejects a zero length", "[framing]") {
    const std::vector<std::uint8_t> header{0x00, 0x00, 0x00, 0x00};
    CHECK_THROWS_AS(framing::decode_length(as_span(header)), ProtocolError);
}

TEST_CASE("decode_length rejects an oversized frame before allocating", "[framing][security]") {
    // 0xFFFFFFFF bytes. The point is that this is refused on the strength of
    // four header bytes, without reserving anything.
    const std::vector<std::uint8_t> header{0xFF, 0xFF, 0xFF, 0xFF};
    CHECK_THROWS_AS(framing::decode_length(as_span(header), framing::kDefaultMaxFrameSize),
                    ProtocolError);
}

// ---------------------------------------------------------------------------
// Streaming decoder
// ---------------------------------------------------------------------------
TEST_CASE("decoder reassembles a frame split across reads", "[framing]") {
    // The property that matters: one SSL_read is not one message.
    framing::Decoder decoder;
    const auto frame = framing::encode("hello world");

    decoder.feed(std::span<const std::uint8_t>(frame.data(), 2));
    CHECK_FALSE(decoder.next_frame().has_value());

    decoder.feed(std::span<const std::uint8_t>(frame.data() + 2, 5));
    CHECK_FALSE(decoder.next_frame().has_value());

    decoder.feed(std::span<const std::uint8_t>(frame.data() + 7, frame.size() - 7));
    const auto payload = decoder.next_frame();
    REQUIRE(payload.has_value());
    CHECK(*payload == "hello world");
}

TEST_CASE("decoder returns several frames from one read", "[framing]") {
    framing::Decoder decoder;

    std::vector<std::uint8_t> combined;
    for (const auto* text : {"first", "second", "third"}) {
        const auto frame = framing::encode(text);
        combined.insert(combined.end(), frame.begin(), frame.end());
    }
    decoder.feed(as_span(combined));

    CHECK(decoder.next_frame().value() == "first");
    CHECK(decoder.next_frame().value() == "second");
    CHECK(decoder.next_frame().value() == "third");
    CHECK_FALSE(decoder.next_frame().has_value());
}

TEST_CASE("decoder rejects an oversized frame at the header", "[framing][security]") {
    framing::Decoder decoder(1024);
    // Announce 1 MiB against a 1 KiB limit, then send only the header. The
    // rejection must happen now, not after the body has been buffered.
    const std::vector<std::uint8_t> header{0x00, 0x10, 0x00, 0x00};
    CHECK_THROWS_AS(decoder.feed(as_span(header)), ProtocolError);
}

TEST_CASE("decoder rejects a zero-length frame header", "[framing]") {
    framing::Decoder decoder;
    const std::vector<std::uint8_t> header{0x00, 0x00, 0x00, 0x00};
    CHECK_THROWS_AS(decoder.feed(as_span(header)), ProtocolError);
}

TEST_CASE("decoder refuses an invalid maximum frame size", "[framing]") {
    CHECK_THROWS_AS(framing::Decoder(0), ProtocolError);
    CHECK_THROWS_AS(framing::Decoder(framing::kAbsoluteMaxFrameSize + 1), ProtocolError);
}

TEST_CASE("decoder reclaims buffer space across many frames", "[framing]") {
    // Regression guard: a long-lived connection must not accumulate consumed
    // bytes indefinitely.
    framing::Decoder decoder;
    for (int i = 0; i < 1000; ++i) {
        const auto frame = framing::encode("payload");
        decoder.feed(as_span(frame));
        REQUIRE(decoder.next_frame().value() == "payload");
    }
    CHECK(decoder.buffered_bytes() < 1024);
}

// ---------------------------------------------------------------------------
// UTF-8 validation
// ---------------------------------------------------------------------------
TEST_CASE("is_valid_utf8 accepts well-formed input", "[utf8]") {
    CHECK(is_valid_utf8(""));
    CHECK(is_valid_utf8("plain ascii"));
    CHECK(is_valid_utf8("\xC3\xA9"));                  // e-acute, 2 bytes
    CHECK(is_valid_utf8("\xE2\x82\xAC"));              // euro sign, 3 bytes
    CHECK(is_valid_utf8("\xF0\x9F\x94\x92"));          // lock emoji, 4 bytes
}

TEST_CASE("is_valid_utf8 rejects malformed sequences", "[utf8][security]") {
    CHECK_FALSE(is_valid_utf8("\x80"));                // continuation byte first
    CHECK_FALSE(is_valid_utf8("\xC3"));                // truncated 2-byte form
    CHECK_FALSE(is_valid_utf8("\xE2\x82"));            // truncated 3-byte form
    CHECK_FALSE(is_valid_utf8("\xC3\x28"));            // bad continuation byte
    CHECK_FALSE(is_valid_utf8("\xF8\x88\x80\x80\x80"));  // 5-byte form, not UTF-8
}

TEST_CASE("is_valid_utf8 rejects overlong encodings", "[utf8][security]") {
    // An overlong encoding gives the same character two byte representations,
    // which is a classic way to slip a value past a filter that only checks one.
    CHECK_FALSE(is_valid_utf8("\xC0\xAF"));            // overlong '/'
    CHECK_FALSE(is_valid_utf8("\xE0\x80\xAF"));        // overlong '/', 3 bytes
    CHECK_FALSE(is_valid_utf8("\xF0\x80\x80\xAF"));    // overlong '/', 4 bytes
}

TEST_CASE("is_valid_utf8 rejects surrogates and out-of-range code points", "[utf8][security]") {
    CHECK_FALSE(is_valid_utf8("\xED\xA0\x80"));        // U+D800, a lone surrogate
    CHECK_FALSE(is_valid_utf8("\xF4\x90\x80\x80"));    // above U+10FFFF
}

// ---------------------------------------------------------------------------
// Message parsing
// ---------------------------------------------------------------------------
TEST_CASE("Message::parse accepts a well-formed request", "[message]") {
    const auto message = Message::parse(R"({
        "protocol_version": 1,
        "message_id": "11111111-1111-4111-8111-111111111111",
        "type": "telemetry",
        "timestamp": "2026-08-05T10:00:00.000Z",
        "payload": {"device_id": "sensor-001", "temperature": 24.6, "status": "normal"}
    })");

    CHECK(message.protocol_version == 1);
    CHECK(message.type == MessageType::Telemetry);
    CHECK(message.message_id == "11111111-1111-4111-8111-111111111111");
    CHECK(message.payload["device_id"] == "sensor-001");
}

TEST_CASE("Message::parse rejects invalid JSON", "[message]") {
    CHECK_THROWS_AS(Message::parse("{not json"), ProtocolError);
    CHECK_THROWS_AS(Message::parse(""), ProtocolError);
}

TEST_CASE("Message::parse rejects a non-object document", "[message]") {
    CHECK_THROWS_AS(Message::parse("[1,2,3]"), ProtocolError);
    CHECK_THROWS_AS(Message::parse("\"a string\""), ProtocolError);
}

TEST_CASE("Message::parse rejects invalid UTF-8", "[message][security]") {
    CHECK_THROWS_AS(Message::parse("{\"protocol_version\":1,\"type\":\"ping\",\"x\":\"\xC3\"}"),
                    ProtocolError);
}

TEST_CASE("Message::parse requires mandatory fields", "[message]") {
    CHECK_THROWS_AS(Message::parse(R"({"type":"ping"})"), ProtocolError);
    CHECK_THROWS_AS(Message::parse(R"({"protocol_version":1})"), ProtocolError);
}

TEST_CASE("Message::parse rejects an unsupported protocol version", "[message]") {
    CHECK_THROWS_AS(Message::parse(R"({"protocol_version":2,"type":"ping"})"), ProtocolError);
    CHECK_THROWS_AS(Message::parse(R"({"protocol_version":0,"type":"ping"})"), ProtocolError);
    CHECK_THROWS_AS(Message::parse(R"({"protocol_version":"1","type":"ping"})"), ProtocolError);
}

TEST_CASE("Message::parse rejects an unknown message type", "[message]") {
    CHECK_THROWS_AS(Message::parse(R"({"protocol_version":1,"type":"exec"})"), ProtocolError);
    CHECK_THROWS_AS(Message::parse(R"({"protocol_version":1,"type":42})"), ProtocolError);
}

TEST_CASE("Message::parse rejects excessive nesting", "[message][security]") {
    // Deeply nested documents are a cheap way to burn CPU or overflow a
    // recursive consumer, so the depth is capped before interpretation.
    std::string deep = R"({"protocol_version":1,"type":"echo","payload":)";
    for (int i = 0; i < kMaxJsonDepth + 5; ++i) {
        deep += "{\"a\":";
    }
    deep += "1";
    for (int i = 0; i < kMaxJsonDepth + 5; ++i) {
        deep += "}";
    }
    deep += "}";

    CHECK_THROWS_AS(Message::parse(deep), ProtocolError);
}

TEST_CASE("telemetry messages require a device id", "[message]") {
    CHECK_THROWS_AS(
        Message::parse(R"({"protocol_version":1,"type":"telemetry","payload":{"t":1}})"),
        ProtocolError);
    CHECK_THROWS_AS(
        Message::parse(R"({"protocol_version":1,"type":"telemetry","payload":{"device_id":7}})"),
        ProtocolError);
}

TEST_CASE("Message::parse rejects an over-long message id", "[message]") {
    const std::string long_id(200, 'a');
    const std::string doc =
        R"({"protocol_version":1,"type":"ping","message_id":")" + long_id + R"("})";
    CHECK_THROWS_AS(Message::parse(doc), ProtocolError);
}

TEST_CASE("a message survives a serialize/parse round trip", "[message]") {
    const Message original = Message::make_request(
        MessageType::Telemetry,
        nlohmann::json{{"device_id", "sensor-001"}, {"temperature", 24.6}});

    const Message restored = Message::parse(original.serialize());

    CHECK(restored.protocol_version == original.protocol_version);
    CHECK(restored.type == original.type);
    CHECK(restored.message_id == original.message_id);
    CHECK(restored.payload["device_id"] == "sensor-001");
}

TEST_CASE("an acknowledgement echoes the request id", "[message]") {
    // This is what lets a client correlate replies when several messages are
    // in flight on one connection.
    const Message request = Message::make_request(MessageType::Ping);
    const Message ack = Message::make_acknowledgement(request);

    CHECK(ack.message_id == request.message_id);
    CHECK(ack.type == MessageType::Acknowledgement);
    REQUIRE(ack.status.has_value());
    CHECK(*ack.status == "accepted");
}

// ---------------------------------------------------------------------------
// Identifiers and timestamps
// ---------------------------------------------------------------------------
TEST_CASE("generate_uuid_v4 produces a well-formed version 4 UUID", "[uuid]") {
    const std::string uuid = generate_uuid_v4();

    REQUIRE(uuid.size() == 36);
    CHECK(uuid[8] == '-');
    CHECK(uuid[13] == '-');
    CHECK(uuid[18] == '-');
    CHECK(uuid[23] == '-');
    CHECK(uuid[14] == '4');                                    // version nibble
    CHECK((uuid[19] == '8' || uuid[19] == '9' ||
           uuid[19] == 'a' || uuid[19] == 'b'));               // RFC 4122 variant
}

TEST_CASE("generate_uuid_v4 does not repeat", "[uuid]") {
    std::vector<std::string> seen;
    for (int i = 0; i < 100; ++i) {
        const std::string uuid = generate_uuid_v4();
        CHECK(std::find(seen.begin(), seen.end(), uuid) == seen.end());
        seen.push_back(uuid);
    }
}

TEST_CASE("iso8601_now returns a UTC timestamp with milliseconds", "[time]") {
    const std::string now = iso8601_now();

    REQUIRE(now.size() == 24);          // YYYY-MM-DDTHH:MM:SS.mmmZ
    CHECK(now[4] == '-');
    CHECK(now[10] == 'T');
    CHECK(now[19] == '.');
    CHECK(now.back() == 'Z');           // UTC, not a local offset
}

TEST_CASE("message type names round trip", "[message]") {
    for (const auto type : {MessageType::Ping, MessageType::Echo, MessageType::Telemetry,
                            MessageType::Capabilities, MessageType::Close,
                            MessageType::Acknowledgement, MessageType::Pong, MessageType::Error}) {
        const auto name = to_string(type);
        const auto parsed = message_type_from_string(name);
        REQUIRE(parsed.has_value());
        CHECK(*parsed == type);
    }
    CHECK_FALSE(message_type_from_string("nonexistent").has_value());
}
