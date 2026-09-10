#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <vector>

namespace point::compression {

enum class Profile {
    Fast,
    Balanced
};

// Point Fast Compression (PFC1): a bounded, dependency-free LZ codec with
// sampling-based pruning and an automatic raw fallback. The returned envelope
// always contains a CRC32 and the original byte length.
std::vector<std::uint8_t> encode_fast(
    std::span<const std::uint8_t> input);
std::vector<std::uint8_t> encode_balanced(
    std::span<const std::uint8_t> input);

// Decodes PFC1 data. Throws std::runtime_error for malformed, truncated, or
// corrupted input. The output is capped to max_output_bytes before allocation.
std::vector<std::uint8_t> decode_fast(
    std::span<const std::uint8_t> encoded,
    std::size_t max_output_bytes = 64u * 1024u * 1024u);

bool is_fast_envelope(std::span<const std::uint8_t> bytes) noexcept;

struct FileResult {
    std::uint64_t input_bytes = 0;
    std::uint64_t output_bytes = 0;
    std::uint64_t compressed_blocks = 0;
    std::uint64_t raw_blocks = 0;
};

// Streaming PFA1 file container. Data is processed in independent 1 MiB PFC1
// blocks and published atomically, keeping memory use bounded for large files.
FileResult compress_file_fast(
    const std::filesystem::path& input,
    const std::filesystem::path& output);
FileResult compress_file(
    const std::filesystem::path& input,
    const std::filesystem::path& output,
    Profile profile);
FileResult decompress_file_fast(
    const std::filesystem::path& input,
    const std::filesystem::path& output,
    std::uint64_t max_output_bytes = 2ull * 1024ull * 1024ull * 1024ull);

}  // namespace point::compression
