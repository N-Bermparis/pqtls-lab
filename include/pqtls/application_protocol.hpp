#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace pqtls {

/// Wire format (spec section 7):
///
///   +--------------------+---------------------------------+
///   | uint32 big-endian  | N bytes UTF-8 JSON              |
///   | payload length N   |                                 |
///   +--------------------+---------------------------------+
///
/// TLS is a stream, not a message boundary. A single SSL_read may return part
/// of a frame or several frames; the length prefix is what makes the boundary
/// explicit. Nothing in this file assumes one read equals one message.
namespace framing {

inline constexpr std::size_t kHeaderSize = 4;

/// Default maximum accepted payload, 1 MiB (spec section 7).
inline constexpr std::uint32_t kDefaultMaxFrameSize = 1024U * 1024U;

/// Hard ceiling. Even an operator-supplied maximum cannot exceed this, so a
/// typo in a config file cannot turn into a memory-exhaustion primitive.
inline constexpr std::uint32_t kAbsoluteMaxFrameSize = 64U * 1024U * 1024U;

/// Serialise `payload` into a length-prefixed frame.
/// @throws ProtocolError when the payload exceeds `max_frame_size`.
[[nodiscard]] std::vector<std::uint8_t> encode(std::string_view payload,
                                               std::uint32_t max_frame_size = kDefaultMaxFrameSize);

/// Read the 4-byte length prefix.
/// @throws ProtocolError when `header` is not exactly 4 bytes, when the length
///         is zero, or when it exceeds `max_frame_size`.
[[nodiscard]] std::uint32_t decode_length(std::span<const std::uint8_t> header,
                                          std::uint32_t max_frame_size = kDefaultMaxFrameSize);

/// Incremental frame reassembler for a byte stream.
///
/// Feed it whatever arrives; pull out complete frames. It never allocates based
/// on an unvalidated length, and it rejects an oversized frame at the moment
/// the header is parsed rather than after buffering the body.
class Decoder {
  public:
    explicit Decoder(std::uint32_t max_frame_size = kDefaultMaxFrameSize);

    /// Append raw bytes received from the transport.
    /// @throws ProtocolError when a frame header announces an illegal length.
    void feed(std::span<const std::uint8_t> data);

    /// Extract the next complete frame payload, or nullopt if more bytes are
    /// needed.
    [[nodiscard]] std::optional<std::string> next_frame();

    [[nodiscard]] std::size_t buffered_bytes() const noexcept { return buffer_.size(); }
    [[nodiscard]] std::uint32_t max_frame_size() const noexcept { return max_frame_size_; }

    void reset() noexcept;

  private:
    std::uint32_t max_frame_size_;
    std::vector<std::uint8_t> buffer_;
    std::size_t consumed_ = 0;
};

}  // namespace framing

/// Application message types (spec section 7).
enum class MessageType {
    Ping,
    Echo,
    Telemetry,
    Capabilities,
    Close,
    Acknowledgement,
    Pong,
    Error,
};

[[nodiscard]] std::string_view to_string(MessageType type) noexcept;
[[nodiscard]] std::optional<MessageType> message_type_from_string(std::string_view name) noexcept;

/// The only application protocol version this build speaks.
inline constexpr int kProtocolVersion = 1;

/// Maximum accepted JSON nesting depth. Deeply nested documents are a cheap way
/// to burn CPU or blow the stack in a recursive parser, so the limit is checked
/// before the document is interpreted.
inline constexpr int kMaxJsonDepth = 16;

/// A validated application message.
struct Message {
    int protocol_version = kProtocolVersion;
    std::string message_id;
    MessageType type = MessageType::Ping;
    std::string timestamp;              ///< ISO-8601, UTC.
    std::optional<std::string> status;  ///< Responses only.
    nlohmann::json payload = nlohmann::json::object();

    /// Parse and fully validate a JSON frame payload.
    ///
    /// Rejects: invalid UTF-8, invalid JSON, unknown protocol versions, missing
    /// mandatory fields, unknown message types and excessive nesting.
    /// @throws ProtocolError on any violation.
    [[nodiscard]] static Message parse(std::string_view json_text);

    [[nodiscard]] nlohmann::json to_json() const;
    [[nodiscard]] std::string serialize() const;

    /// Build a client request with a fresh UUID and current timestamp.
    [[nodiscard]] static Message make_request(MessageType type, nlohmann::json payload = {});

    /// Build the acknowledgement for `request`, echoing its message id so the
    /// client can correlate the exchange.
    [[nodiscard]] static Message make_acknowledgement(const Message& request,
                                                      std::string status = "accepted");

    [[nodiscard]] static Message make_error(const Message* request, std::string_view reason);
};

/// Return true if `bytes` is well-formed UTF-8.
///
/// Written out rather than delegated because the JSON library's behaviour on
/// invalid UTF-8 is configurable, and we want a hard, independent gate.
[[nodiscard]] bool is_valid_utf8(std::string_view bytes) noexcept;

/// RFC 4122 version 4 UUID, generated from the OpenSSL CSPRNG.
[[nodiscard]] std::string generate_uuid_v4();

/// Current time as an ISO-8601 UTC string with millisecond precision.
[[nodiscard]] std::string iso8601_now();

}  // namespace pqtls
