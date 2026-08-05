#include <catch2/catch_test_macros.hpp>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

#include "pqtls/error.hpp"
#include "pqtls/metrics.hpp"

using namespace pqtls;

namespace {

ConnectionMetrics sample_metrics() {
    ConnectionMetrics metrics;
    metrics.experiment_id = "test-001";
    metrics.connection_id = "11111111-1111-4111-8111-111111111111";
    metrics.role = Role::Client;
    metrics.requested_profile = "hybrid-x25519-mlkem768";
    metrics.negotiated_profile = "hybrid-x25519-mlkem768";
    metrics.tls_version = "TLSv1.3";
    metrics.negotiated_group = "X25519MLKEM768";
    metrics.cipher_suite = "TLS_AES_256_GCM_SHA384";
    metrics.authentication = "ecdsa_secp256r1_sha256";
    metrics.handshake_ms = 12.41;
    metrics.connection_ms = 15.08;
    metrics.application_bytes_sent = 164;
    metrics.application_bytes_received = 141;
    metrics.session_reused = false;
    metrics.success = true;
    metrics.error_category = ErrorCategory::None;
    metrics.peer_address = "127.0.0.1:8443";
    metrics.protocol_message_count = 2;
    metrics.timestamp = "2026-08-05T10:00:00.000Z";
    metrics.pq_key_establishment = true;
    metrics.hybrid_key_establishment = true;
    metrics.pq_authentication = false;
    return metrics;
}

/// A temporary file that removes itself, so a failing assertion cannot leave
/// stray files in the build tree.
class TempFile {
  public:
    explicit TempFile(std::string name)
        : path_(std::filesystem::temp_directory_path() / std::move(name)) {
        std::filesystem::remove(path_);
    }

    TempFile(const TempFile&) = delete;
    TempFile& operator=(const TempFile&) = delete;

    ~TempFile() {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }

    [[nodiscard]] std::string string() const { return path_.string(); }
    [[nodiscard]] const std::filesystem::path& path() const { return path_; }

    [[nodiscard]] std::vector<std::string> lines() const {
        std::vector<std::string> out;
        std::ifstream stream(path_);
        std::string line;
        while (std::getline(stream, line)) {
            if (!line.empty()) {
                out.push_back(line);
            }
        }
        return out;
    }

  private:
    std::filesystem::path path_;
};

}  // namespace

// ---------------------------------------------------------------------------
// Serialisation
// ---------------------------------------------------------------------------
TEST_CASE("metrics serialise every documented field", "[metrics]") {
    const auto json = sample_metrics().to_json();

    for (const auto* field :
         {"schema_version", "experiment_id", "connection_id", "role", "requested_profile",
          "negotiated_group", "tls_version", "cipher_suite", "authentication", "handshake_ms",
          "connection_ms", "application_bytes_sent", "application_bytes_received",
          "session_reused", "success", "error_category", "timestamp"}) {
        INFO("field: " << field);
        CHECK(json.contains(field));
    }
}

TEST_CASE("the three post-quantum properties are separate fields", "[metrics][security]") {
    // Collapsing these into one boolean is exactly how a project ends up
    // claiming post-quantum authentication it does not have.
    const auto json = sample_metrics().to_json();

    REQUIRE(json.contains("pq_key_establishment"));
    REQUIRE(json.contains("hybrid_key_establishment"));
    REQUIRE(json.contains("pq_authentication"));

    CHECK(json["pq_key_establishment"] == true);
    CHECK(json["hybrid_key_establishment"] == true);
    CHECK(json["pq_authentication"] == false);
}

TEST_CASE("a JSONL line contains no embedded newline", "[metrics]") {
    // One record must be exactly one line, or the file is not valid JSON Lines.
    const std::string line = sample_metrics().to_jsonl_line();
    CHECK(line.find('\n') == std::string::npos);
    CHECK_NOTHROW(nlohmann::json::parse(line));
}

TEST_CASE("a successful record reports a null error category", "[metrics]") {
    const auto json = sample_metrics().to_json();
    CHECK(json["error_category"].is_null());
}

TEST_CASE("a failed record names its error category", "[metrics]") {
    auto metrics = sample_metrics();
    metrics.success = false;
    metrics.error_category = ErrorCategory::TlsPolicy;
    metrics.error_message = "downgrade policy violation";

    const auto json = metrics.to_json();
    CHECK(json["success"] == false);
    CHECK(json["error_category"] == "tls-policy");
    CHECK(json["error_message"] == "downgrade policy violation");
}

TEST_CASE("unmeasured optional fields serialise as null, not zero", "[metrics]") {
    // "Not measured" and "measured as nothing" are different facts, and an
    // analysis that cannot tell them apart will average zeros into its results.
    const auto json = sample_metrics().to_json();
    CHECK(json["transport_bytes_sent"].is_null());
    CHECK(json["peak_memory_kib"].is_null());
    CHECK(json["process_cpu_user_ms"].is_null());
}

TEST_CASE("measured optional fields serialise as numbers", "[metrics]") {
    auto metrics = sample_metrics();
    metrics.peak_memory_kib = 20480;
    metrics.process_cpu_user_ms = 12.5;

    const auto json = metrics.to_json();
    CHECK(json["peak_memory_kib"] == 20480);
    CHECK(json["process_cpu_user_ms"] == 12.5);
}

TEST_CASE("the schema version is pinned", "[metrics]") {
    // A bump here must be accompanied by a change to schemas/metrics.schema.json
    // and to tools/result_validator.py.
    CHECK(kMetricsSchemaVersion == 1);
    CHECK(sample_metrics().to_json()["schema_version"] == 1);
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------
TEST_CASE("the writer produces one line per record", "[metrics][writer]") {
    const TempFile file("pqtls-metrics-lines.jsonl");
    {
        MetricsWriter writer(file.string());
        REQUIRE(writer.enabled());
        for (int i = 0; i < 5; ++i) {
            writer.write(sample_metrics());
        }
    }

    const auto lines = file.lines();
    REQUIRE(lines.size() == 5);
    for (const auto& line : lines) {
        CHECK_NOTHROW(nlohmann::json::parse(line));
    }
}

TEST_CASE("the writer appends and never truncates", "[metrics][writer]") {
    // A benchmark run must not destroy the results of an earlier one.
    const TempFile file("pqtls-metrics-append.jsonl");
    {
        MetricsWriter first(file.string());
        first.write(sample_metrics());
    }
    {
        MetricsWriter second(file.string());
        second.write(sample_metrics());
        second.write(sample_metrics());
    }

    CHECK(file.lines().size() == 3);
}

TEST_CASE("the writer creates missing parent directories", "[metrics][writer]") {
    const auto directory = std::filesystem::temp_directory_path() / "pqtls-nested-test" / "deep";
    const auto path = directory / "metrics.jsonl";
    std::filesystem::remove_all(std::filesystem::temp_directory_path() / "pqtls-nested-test");

    {
        MetricsWriter writer(path.string());
        writer.write(sample_metrics());
    }
    CHECK(std::filesystem::exists(path));

    std::error_code ec;
    std::filesystem::remove_all(std::filesystem::temp_directory_path() / "pqtls-nested-test", ec);
}

TEST_CASE("a default-constructed writer is inert", "[metrics][writer]") {
    MetricsWriter writer;
    CHECK_FALSE(writer.enabled());
    CHECK_NOTHROW(writer.write(sample_metrics()));  // silently discarded
}

TEST_CASE("the writer is safe under concurrent use", "[metrics][writer][concurrency]") {
    // The server writes one record per connection from a pool of worker
    // threads. Interleaved writes would corrupt the JSONL structure.
    const TempFile file("pqtls-metrics-threads.jsonl");
    constexpr int kThreads = 8;
    constexpr int kPerThread = 50;

    {
        MetricsWriter writer(file.string());
        std::vector<std::thread> threads;
        threads.reserve(kThreads);
        for (int t = 0; t < kThreads; ++t) {
            threads.emplace_back([&writer] {
                for (int i = 0; i < kPerThread; ++i) {
                    writer.write(sample_metrics());
                }
            });
        }
        for (auto& thread : threads) {
            thread.join();
        }
    }

    const auto lines = file.lines();
    REQUIRE(lines.size() == kThreads * kPerThread);
    for (const auto& line : lines) {
        INFO("line: " << line);
        CHECK_NOTHROW(nlohmann::json::parse(line));
    }
}

// ---------------------------------------------------------------------------
// Timing and resource sampling
// ---------------------------------------------------------------------------
TEST_CASE("the stopwatch measures forward elapsed time", "[metrics][timing]") {
    const Stopwatch stopwatch;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    const double elapsed = stopwatch.elapsed_ms();

    CHECK(elapsed >= 5.0);      // generous lower bound: scheduling is not exact
    CHECK(elapsed < 5000.0);
}

TEST_CASE("resetting the stopwatch restarts the measurement", "[metrics][timing]") {
    Stopwatch stopwatch;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    stopwatch.reset();
    CHECK(stopwatch.elapsed_ms() < 20.0);
}

TEST_CASE("resource usage sampling does not throw", "[metrics][resources]") {
    // Fields are allowed to be absent on platforms that do not expose them;
    // what must not happen is a throw from a metrics path.
    ResourceUsage usage;
    CHECK_NOTHROW(usage = ResourceUsage::sample());
    if (usage.cpu_user_ms.has_value()) {
        CHECK(*usage.cpu_user_ms >= 0.0);
    }
    if (usage.peak_memory_kib.has_value()) {
        CHECK(*usage.peak_memory_kib > 0);
    }
}

TEST_CASE("role names serialise as expected", "[metrics]") {
    CHECK(to_string(Role::Client) == "client");
    CHECK(to_string(Role::Server) == "server");
}
