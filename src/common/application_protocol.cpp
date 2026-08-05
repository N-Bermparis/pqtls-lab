#include "pqtls/application_protocol.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <utility>

#include <openssl/rand.h>

#include "pqtls/error.hpp"

namespace pqtls {
namespace framing {

std::vector<std::uint8_t> encode(std::string_view payload, std::uint32_t max_frame_size) {
    if (max_frame_size > kAbsoluteMaxFrameSize) {
        throw ProtocolError("configured maximum frame size exceeds the absolute ceiling of " +
                            std::to_string(kAbsoluteMaxFrameSize) + " bytes");
    }
    if (payload.empty()) {
        throw ProtocolError("refusing to encode a zero-length frame");
    }
    if (payload.size() > max_frame_size) {
        throw ProtocolError("payload of " + std::to_string(payload.size()) +
                            " bytes exceeds the maximum frame size of " +
                            std::to_string(max_frame_size) + " bytes");
    }

    const auto length = static_cast<std::uint32_t>(payload.size());

    std::vector<std::uint8_t> frame;
    frame.reserve(kHeaderSize + payload.size());
    // Big-endian (network order) length prefix, written byte by byte so the
    // encoding does not depend on host endianness.
    frame.push_back(static_cast<std::uint8_t>((length >> 24) & 0xFFU));
    frame.push_back(static_cast<std::uint8_t>((length >> 16) & 0xFFU));
    frame.push_back(static_cast<std::uint8_t>((length >> 8) & 0xFFU));
    frame.push_back(static_cast<std::uint8_t>(length & 0xFFU));
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

std::uint32_t decode_length(std::span<const std::uint8_t> header, std::uint32_t max_frame_size) {
    if (header.size() != kHeaderSize) {
        throw ProtocolError("frame header must be exactly " + std::to_string(kHeaderSize) +
                            " bytes, got " + std::to_string(header.size()));
    }

    const std::uint32_t length = (static_cast<std::uint32_t>(header[0]) << 24) |
                                 (static_cast<std::uint32_t>(header[1]) << 16) |
                                 (static_cast<std::uint32_t>(header[2]) << 8) |
                                 static_cast<std::uint32_t>(header[3]);

    if (length == 0) {
        throw ProtocolError("frame announces a zero-length payload, which is never valid");
    }
    if (length > max_frame_size) {
        // Rejected here, before any allocation of that size. An attacker who
        // can write four bytes must not be able to make us reserve gigabytes.
        throw ProtocolError("frame announces " + std::to_string(length) +
                            " bytes, exceeding the maximum frame size of " +
                            std::to_string(max_frame_size) + " bytes");
    }
    return length;
}

Decoder::Decoder(std::uint32_t max_frame_size) : max_frame_size_(max_frame_size) {
    if (max_frame_size_ == 0 || max_frame_size_ > kAbsoluteMaxFrameSize) {
        throw ProtocolError("invalid maximum frame size " + std::to_string(max_frame_size) +
                            "; must be in [1, " + std::to_string(kAbsoluteMaxFrameSize) + "]");
    }
}

void Decoder::feed(std::span<const std::uint8_t> data) {
    // Reclaim space from frames already handed out before growing the buffer,
    // so a long-lived connection does not accumulate consumed bytes.
    if (consumed_ > 0 && consumed_ == buffer_.size()) {
        buffer_.clear();
        consumed_ = 0;
    } else if (consumed_ > (kHeaderSize + max_frame_size_)) {
        buffer_.erase(buffer_.begin(),
                      buffer_.begin() + static_cast<std::ptrdiff_t>(consumed_));
        consumed_ = 0;
    }

    buffer_.insert(buffer_.end(), data.begin(), data.end());

    // Validate the header as soon as it is complete rather than after the body
    // arrives; an oversized frame is refused before we buffer its contents.
    if (buffer_.size() - consumed_ >= kHeaderSize) {
        const std::span<const std::uint8_t> header(buffer_.data() + consumed_, kHeaderSize);
        (void)decode_length(header, max_frame_size_);  // throws on violation
    }
}

std::optional<std::string> Decoder::next_frame() {
    const std::size_t available = buffer_.size() - consumed_;
    if (available < kHeaderSize) {
        return std::nullopt;
    }

    const std::span<const std::uint8_t> header(buffer_.data() + consumed_, kHeaderSize);
    const std::uint32_t length = decode_length(header, max_frame_size_);

    if (available < kHeaderSize + length) {
        return std::nullopt;
    }

    const auto* body = reinterpret_cast<const char*>(buffer_.data() + consumed_ + kHeaderSize);
    std::string payload(body, length);
    consumed_ += kHeaderSize + length;

    if (consumed_ == buffer_.size()) {
        buffer_.clear();
        consumed_ = 0;
    }

    return payload;
}

void Decoder::reset() noexcept {
    buffer_.clear();
    consumed_ = 0;
}

}  // namespace framing

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

std::string_view to_string(MessageType type) noexcept {
    switch (type) {
        case MessageType::Ping:            return "ping";
        case MessageType::Echo:            return "echo";
        case MessageType::Telemetry:       return "telemetry";
        case MessageType::Capabilities:    return "capabilities";
        case MessageType::Close:           return "close";
        case MessageType::Acknowledgement: return "acknowledgement";
        case MessageType::Pong:            return "pong";
        case MessageType::Error:           return "error";
    }
    return "error";
}

std::optional<MessageType> message_type_from_string(std::string_view name) noexcept {
    if (name == "ping")            return MessageType::Ping;
    if (name == "echo")            return MessageType::Echo;
    if (name == "telemetry")       return MessageType::Telemetry;
    if (name == "capabilities")    return MessageType::Capabilities;
    if (name == "close")           return MessageType::Close;
    if (name == "acknowledgement") return MessageType::Acknowledgement;
    if (name == "pong")            return MessageType::Pong;
    if (name == "error")           return MessageType::Error;
    return std::nullopt;
}

bool is_valid_utf8(std::string_view bytes) noexcept {
    const auto* p = reinterpret_cast<const unsigned char*>(bytes.data());
    const auto* const end = p + bytes.size();

    while (p < end) {
        const unsigned char first = *p;

        if (first < 0x80U) {
            ++p;
            continue;
        }

        int extra = 0;
        unsigned int code_point = 0;
        if ((first & 0xE0U) == 0xC0U) {
            extra = 1;
            code_point = first & 0x1FU;
        } else if ((first & 0xF0U) == 0xE0U) {
            extra = 2;
            code_point = first & 0x0FU;
        } else if ((first & 0xF8U) == 0xF0U) {
            extra = 3;
            code_point = first & 0x07U;
        } else {
            return false;  // continuation byte in leading position, or 5+ byte form
        }

        if (p + extra >= end) {
            return false;  // truncated sequence
        }

        for (int i = 1; i <= extra; ++i) {
            const unsigned char cont = p[i];
            if ((cont & 0xC0U) != 0x80U) {
                return false;
            }
            code_point = (code_point << 6U) | (cont & 0x3FU);
        }

        // Reject overlong encodings, surrogates and out-of-range code points.
        // These are the forms that let the same logical string have several
        // byte representations, which is a classic filter-bypass vector.
        if (extra == 1 && code_point < 0x80U) return false;
        if (extra == 2 && code_point < 0x800U) return false;
        if (extra == 3 && code_point < 0x10000U) return false;
        if (code_point > 0x10FFFFU) return false;
        if (code_point >= 0xD800U && code_point <= 0xDFFFU) return false;

        p += extra + 1;
    }

    return true;
}

namespace {

/// Depth check performed before we walk the document for semantics. nlohmann's
/// parser is iterative and will not blow the stack, but downstream consumers
/// (including our own serialisation) may recurse.
int json_depth(const nlohmann::json& value, int current = 0) {
    if (current > kMaxJsonDepth) {
        return current;
    }
    if (!value.is_structured()) {
        return current;
    }
    int deepest = current;
    for (const auto& child : value) {
        deepest = std::max(deepest, json_depth(child, current + 1));
        if (deepest > kMaxJsonDepth) {
            break;
        }
    }
    return deepest;
}

}  // namespace

Message Message::parse(std::string_view json_text) {
    if (json_text.empty()) {
        throw ProtocolError("empty application message");
    }

    if (!is_valid_utf8(json_text)) {
        throw ProtocolError("application message is not valid UTF-8");
    }

    nlohmann::json doc;
    try {
        // allow_exceptions=true, ignore_comments=false: we want strict JSON.
        doc = nlohmann::json::parse(json_text);
    } catch (const nlohmann::json::parse_error& e) {
        throw ProtocolError(std::string("application message is not valid JSON: ") + e.what());
    }

    if (!doc.is_object()) {
        throw ProtocolError("application message must be a JSON object");
    }

    if (json_depth(doc) > kMaxJsonDepth) {
        throw ProtocolError("application message exceeds the maximum JSON nesting depth of " +
                            std::to_string(kMaxJsonDepth));
    }

    Message message;

    if (!doc.contains("protocol_version")) {
        throw ProtocolError("application message is missing the mandatory field 'protocol_version'");
    }
    if (!doc["protocol_version"].is_number_integer()) {
        throw ProtocolError("'protocol_version' must be an integer");
    }
    message.protocol_version = doc["protocol_version"].get<int>();
    if (message.protocol_version != kProtocolVersion) {
        throw ProtocolError("unsupported protocol version " +
                            std::to_string(message.protocol_version) + "; this build speaks " +
                            std::to_string(kProtocolVersion) + " only");
    }

    if (!doc.contains("type")) {
        throw ProtocolError("application message is missing the mandatory field 'type'");
    }
    if (!doc["type"].is_string()) {
        throw ProtocolError("'type' must be a string");
    }
    const auto type_name = doc["type"].get<std::string>();
    const auto parsed_type = message_type_from_string(type_name);
    if (!parsed_type) {
        throw ProtocolError("unknown message type '" + type_name + "'");
    }
    message.type = *parsed_type;

    if (doc.contains("message_id")) {
        if (!doc["message_id"].is_string()) {
            throw ProtocolError("'message_id' must be a string");
        }
        message.message_id = doc["message_id"].get<std::string>();
        if (message.message_id.size() > 128) {
            throw ProtocolError("'message_id' is longer than the 128-character limit");
        }
    } else {
        message.message_id = generate_uuid_v4();
    }

    if (doc.contains("timestamp")) {
        if (!doc["timestamp"].is_string()) {
            throw ProtocolError("'timestamp' must be an ISO-8601 string");
        }
        message.timestamp = doc["timestamp"].get<std::string>();
    } else {
        message.timestamp = iso8601_now();
    }

    if (doc.contains("status")) {
        if (!doc["status"].is_string()) {
            throw ProtocolError("'status' must be a string");
        }
        message.status = doc["status"].get<std::string>();
    }

    if (doc.contains("payload")) {
        if (!doc["payload"].is_object()) {
            throw ProtocolError("'payload' must be a JSON object");
        }
        message.payload = doc["payload"];
    }

    // Type-specific mandatory fields.
    if (message.type == MessageType::Telemetry) {
        if (!message.payload.contains("device_id") || !message.payload["device_id"].is_string()) {
            throw ProtocolError("telemetry message requires a string 'payload.device_id'");
        }
    }

    return message;
}

nlohmann::json Message::to_json() const {
    nlohmann::json doc;
    doc["protocol_version"] = protocol_version;
    doc["message_id"] = message_id;
    doc["type"] = to_string(type);
    doc["timestamp"] = timestamp;
    if (status.has_value()) {
        doc["status"] = *status;
    }
    if (!payload.is_null() && !payload.empty()) {
        doc["payload"] = payload;
    }
    return doc;
}

std::string Message::serialize() const {
    return to_json().dump();
}

Message Message::make_request(MessageType type, nlohmann::json payload) {
    Message message;
    message.protocol_version = kProtocolVersion;
    message.message_id = generate_uuid_v4();
    message.type = type;
    message.timestamp = iso8601_now();
    if (!payload.is_null()) {
        message.payload = std::move(payload);
    }
    return message;
}

Message Message::make_acknowledgement(const Message& request, std::string status) {
    Message message;
    message.protocol_version = kProtocolVersion;
    // Echoing the request id is what lets a client correlate responses when
    // several messages are in flight on one connection.
    message.message_id = request.message_id;
    message.type = MessageType::Acknowledgement;
    message.timestamp = iso8601_now();
    message.status = std::move(status);
    return message;
}

Message Message::make_error(const Message* request, std::string_view reason) {
    Message message;
    message.protocol_version = kProtocolVersion;
    message.message_id = request != nullptr ? request->message_id : generate_uuid_v4();
    message.type = MessageType::Error;
    message.timestamp = iso8601_now();
    message.status = "rejected";
    // The reason describes a protocol violation, never internal state that
    // could help an attacker or leak secret material.
    message.payload = nlohmann::json{{"reason", std::string(reason)}};
    return message;
}

std::string generate_uuid_v4() {
    std::array<unsigned char, 16> bytes{};
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        // A failing CSPRNG is not something to paper over with rand().
        throw InternalError("the OpenSSL CSPRNG failed to produce random bytes for a UUID",
                            drain_openssl_errors());
    }

    bytes[6] = static_cast<unsigned char>((bytes[6] & 0x0FU) | 0x40U);  // version 4
    bytes[8] = static_cast<unsigned char>((bytes[8] & 0x3FU) | 0x80U);  // RFC 4122 variant

    static constexpr char kHex[] = "0123456789abcdef";
    std::string uuid;
    uuid.reserve(36);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            uuid.push_back('-');
        }
        uuid.push_back(kHex[(bytes[i] >> 4U) & 0x0FU]);
        uuid.push_back(kHex[bytes[i] & 0x0FU]);
    }
    return uuid;
}

std::string iso8601_now() {
    using namespace std::chrono;
    const auto now = system_clock::now();
    const auto seconds_part = time_point_cast<seconds>(now);
    const auto millis = duration_cast<milliseconds>(now - seconds_part).count();

    const std::time_t tt = system_clock::to_time_t(seconds_part);
    std::tm tm_utc{};
#if defined(_WIN32)
    gmtime_s(&tm_utc, &tt);
#else
    gmtime_r(&tt, &tm_utc);
#endif

    std::array<char, 32> buffer{};
    const std::size_t written =
        std::strftime(buffer.data(), buffer.size(), "%Y-%m-%dT%H:%M:%S", &tm_utc);
    if (written == 0) {
        return "1970-01-01T00:00:00.000Z";
    }

    std::array<char, 40> full{};
    std::snprintf(full.data(), full.size(), "%s.%03dZ", buffer.data(), static_cast<int>(millis));
    return std::string(full.data());
}

}  // namespace pqtls
