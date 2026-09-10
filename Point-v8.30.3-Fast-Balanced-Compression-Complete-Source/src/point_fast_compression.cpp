#include "point_fast_compression.h"

#include <algorithm>
#include <array>
#include <fstream>
#include <limits>
#include <stdexcept>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace point::compression {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic{'P', 'F', 'C', '1'};
constexpr std::size_t kHeaderSize = 25;
constexpr std::uint8_t kRaw = 0;
constexpr std::uint8_t kLz = 1;
constexpr std::uint8_t kLzBalanced = 2;
constexpr std::array<std::uint8_t, 4> kFileMagic{'P', 'F', 'A', '1'};
constexpr std::size_t kFileHeaderSize = 16;
constexpr std::size_t kFileBlockSize = 1024u * 1024u;
constexpr std::size_t kMinimumMatch = 4;
constexpr std::size_t kMaximumMatch = 259;

void append_u32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    for (unsigned shift = 0; shift < 32; shift += 8)
        out.push_back(static_cast<std::uint8_t>(value >> shift));
}

void append_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<std::uint8_t>(value >> shift));
}

std::uint32_t read_u32(std::span<const std::uint8_t> data, std::size_t at) {
    if (at > data.size() || data.size() - at < 4)
        throw std::runtime_error("Compressed workspace header is truncated");
    std::uint32_t value = 0;
    for (unsigned shift = 0; shift < 32; shift += 8)
        value |= static_cast<std::uint32_t>(data[at++]) << shift;
    return value;
}

std::uint64_t read_u64(std::span<const std::uint8_t> data, std::size_t at) {
    if (at > data.size() || data.size() - at < 8)
        throw std::runtime_error("Compressed workspace header is truncated");
    std::uint64_t value = 0;
    for (unsigned shift = 0; shift < 64; shift += 8)
        value |= static_cast<std::uint64_t>(data[at++]) << shift;
    return value;
}

std::uint32_t crc32(std::span<const std::uint8_t> data) noexcept {
    std::uint32_t crc = 0xffffffffu;
    for (const auto byte : data) {
        crc ^= byte;
        for (int bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xedb88320u &
                (0u - (crc & 1u)));
    }
    return ~crc;
}

std::uint32_t load4(std::span<const std::uint8_t> input, std::size_t at) {
    return static_cast<std::uint32_t>(input[at]) |
        (static_cast<std::uint32_t>(input[at + 1]) << 8) |
        (static_cast<std::uint32_t>(input[at + 2]) << 16) |
        (static_cast<std::uint32_t>(input[at + 3]) << 24);
}

std::size_t hash4(std::uint32_t value) noexcept {
    return (value * 2654435761u) >> 16;
}

bool sample_looks_compressible(std::span<const std::uint8_t> input) {
    if (input.size() < 1024) return true;
    std::array<std::uint32_t, 4096> keys{};
    std::array<bool, 4096> used{};
    const std::size_t samples = std::min<std::size_t>(2048, input.size() - 3);
    const std::size_t step = std::max<std::size_t>(1, (input.size() - 3) / samples);
    std::size_t repeats = 0;
    for (std::size_t at = 0; at + 3 < input.size(); at += step) {
        const auto key = load4(input, at);
        const auto slot = hash4(key) & (keys.size() - 1);
        if (used[slot] && keys[slot] == key) {
            if (++repeats >= 8) return true;
        } else {
            used[slot] = true;
            keys[slot] = key;
        }
    }
    return false;
}

std::vector<std::uint8_t> lz_encode(std::span<const std::uint8_t> input) {
    std::array<std::int64_t, 65536> last;
    last.fill(-1);
    std::vector<std::uint8_t> out;
    out.reserve(input.size());
    std::size_t at = 0;
    while (at < input.size()) {
        const auto control_at = out.size();
        out.push_back(0);
        std::uint8_t control = 0;
        for (unsigned token = 0; token < 8 && at < input.size(); ++token) {
            std::size_t match_length = 0;
            std::size_t distance = 0;
            if (at + kMinimumMatch <= input.size()) {
                const auto slot = hash4(load4(input, at));
                const auto candidate = last[slot];
                last[slot] = static_cast<std::int64_t>(at);
                if (candidate >= 0) {
                    distance = at - static_cast<std::size_t>(candidate);
                    if (distance <= 65536) {
                        const auto limit = std::min(
                            kMaximumMatch, input.size() - at);
                        while (match_length < limit &&
                               input[static_cast<std::size_t>(candidate) + match_length] ==
                                   input[at + match_length])
                            ++match_length;
                        if (match_length < kMinimumMatch) match_length = 0;
                    }
                }
            }
            if (match_length != 0) {
                control |= static_cast<std::uint8_t>(1u << token);
                const auto encoded_distance = distance - 1;
                out.push_back(static_cast<std::uint8_t>(encoded_distance));
                out.push_back(static_cast<std::uint8_t>(encoded_distance >> 8));
                out.push_back(static_cast<std::uint8_t>(match_length - kMinimumMatch));
                at += match_length;
            } else {
                out.push_back(input[at++]);
            }
        }
        out[control_at] = control;
    }
    return out;
}

std::vector<std::uint8_t> lz_encode_balanced(
        std::span<const std::uint8_t> input) {
    constexpr std::size_t kCandidateDepth = 8;
    using CandidateSet = std::array<std::int32_t, kCandidateDepth>;
    std::vector<CandidateSet> recent(65536);
    for (auto& set : recent) set.fill(-1);
    std::vector<std::uint8_t> next_slot(65536, 0);

    auto remember = [&](std::size_t position) {
        if (position + kMinimumMatch > input.size() ||
            position > static_cast<std::size_t>(
                std::numeric_limits<std::int32_t>::max()))
            return;
        const auto slot = hash4(load4(input, position));
        auto& cursor = next_slot[slot];
        recent[slot][cursor] = static_cast<std::int32_t>(position);
        cursor = static_cast<std::uint8_t>((cursor + 1) % kCandidateDepth);
    };

    std::vector<std::uint8_t> out;
    out.reserve(input.size());
    std::size_t at = 0;
    while (at < input.size()) {
        const auto control_at = out.size();
        out.push_back(0);
        std::uint8_t control = 0;
        for (unsigned token = 0; token < 8 && at < input.size(); ++token) {
            std::size_t best_length = 0;
            std::size_t best_distance = 0;
            if (at + kMinimumMatch <= input.size()) {
                const auto slot = hash4(load4(input, at));
                for (const auto candidate_value : recent[slot]) {
                    if (candidate_value < 0) continue;
                    const auto candidate =
                        static_cast<std::size_t>(candidate_value);
                    const auto distance = at - candidate;
                    if (distance == 0 || distance > 65536) continue;
                    const auto limit = std::min(
                        kMaximumMatch, input.size() - at);
                    std::size_t length = 0;
                    while (length < limit &&
                           input[candidate + length] == input[at + length])
                        ++length;
                    if (length >= kMinimumMatch && length > best_length) {
                        best_length = length;
                        best_distance = distance;
                        if (length == limit) break;
                    }
                }
                remember(at);
            }
            if (best_length != 0) {
                control |= static_cast<std::uint8_t>(1u << token);
                const auto encoded_distance = best_distance - 1;
                out.push_back(static_cast<std::uint8_t>(encoded_distance));
                out.push_back(static_cast<std::uint8_t>(encoded_distance >> 8));
                out.push_back(static_cast<std::uint8_t>(
                    best_length - kMinimumMatch));
                const auto end = at + best_length;
                for (std::size_t position = at + 1; position < end; ++position)
                    remember(position);
                at = end;
            } else {
                out.push_back(input[at++]);
            }
        }
        out[control_at] = control;
    }
    return out;
}

void read_exact(std::ifstream& input, void* data, std::size_t size) {
    if (size == 0) return;
    input.read(reinterpret_cast<char*>(data),
        static_cast<std::streamsize>(size));
    if (!input) throw std::runtime_error("Compressed file is truncated");
}

void write_exact(std::ofstream& output, const void* data, std::size_t size) {
    if (size == 0) return;
    output.write(reinterpret_cast<const char*>(data),
        static_cast<std::streamsize>(size));
    if (!output) throw std::runtime_error("Compressed file write failed");
}

void write_u32(std::ofstream& output, std::uint32_t value) {
    std::array<std::uint8_t, 4> bytes{};
    for (unsigned shift = 0; shift < 32; shift += 8)
        bytes[shift / 8] = static_cast<std::uint8_t>(value >> shift);
    write_exact(output, bytes.data(), bytes.size());
}

void write_u64(std::ofstream& output, std::uint64_t value) {
    std::array<std::uint8_t, 8> bytes{};
    for (unsigned shift = 0; shift < 64; shift += 8)
        bytes[shift / 8] = static_cast<std::uint8_t>(value >> shift);
    write_exact(output, bytes.data(), bytes.size());
}

std::uint32_t read_stream_u32(std::ifstream& input) {
    std::array<std::uint8_t, 4> bytes{};
    read_exact(input, bytes.data(), bytes.size());
    return read_u32(bytes, 0);
}

std::uint64_t read_stream_u64(std::ifstream& input) {
    std::array<std::uint8_t, 8> bytes{};
    read_exact(input, bytes.data(), bytes.size());
    return read_u64(bytes, 0);
}

void publish_temporary(
        const std::filesystem::path& temporary,
        const std::filesystem::path& output) {
#ifdef _WIN32
    if (!MoveFileExW(temporary.c_str(), output.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        throw std::runtime_error("Compressed file could not be published");
    }
#else
    std::error_code error;
    std::filesystem::rename(temporary, output, error);
    if (error) {
        std::filesystem::remove(output, error);
        error.clear();
        std::filesystem::rename(temporary, output, error);
    }
    if (error) {
        std::filesystem::remove(temporary, error);
        throw std::runtime_error("Compressed file could not be published");
    }
#endif
}

std::filesystem::path temporary_for(const std::filesystem::path& output) {
    auto temporary = output;
    temporary += L".point-writing";
    return temporary;
}

}  // namespace

bool is_fast_envelope(std::span<const std::uint8_t> bytes) noexcept {
    return bytes.size() >= kMagic.size() &&
        std::equal(kMagic.begin(), kMagic.end(), bytes.begin());
}

std::vector<std::uint8_t> encode_with_profile(
    std::span<const std::uint8_t> input, Profile profile);

std::vector<std::uint8_t> encode_fast(
        std::span<const std::uint8_t> input) {
    return encode_with_profile(input, Profile::Fast);
}

std::vector<std::uint8_t> encode_balanced(
        std::span<const std::uint8_t> input) {
    return encode_with_profile(input, Profile::Balanced);
}

std::vector<std::uint8_t> encode_with_profile(
        std::span<const std::uint8_t> input, Profile profile) {
    std::vector<std::uint8_t> payload;
    std::uint8_t method = kRaw;
    if (sample_looks_compressible(input)) {
        auto candidate = profile == Profile::Balanced
            ? lz_encode_balanced(input) : lz_encode(input);
        // Require a useful saving, including the envelope overhead.
        const auto required_saving = profile == Profile::Balanced
            ? std::max<std::size_t>(8, input.size() / 400)
            : std::max<std::size_t>(16, input.size() / 100);
        if (candidate.size() + kHeaderSize + required_saving <
                input.size() + kHeaderSize) {
            method = profile == Profile::Balanced ? kLzBalanced : kLz;
            payload = std::move(candidate);
        }
    }
    if (method == kRaw) payload.assign(input.begin(), input.end());

    std::vector<std::uint8_t> out;
    out.reserve(kHeaderSize + payload.size());
    out.insert(out.end(), kMagic.begin(), kMagic.end());
    out.push_back(method);
    append_u64(out, static_cast<std::uint64_t>(input.size()));
    append_u64(out, static_cast<std::uint64_t>(payload.size()));
    append_u32(out, crc32(input));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

std::vector<std::uint8_t> decode_fast(
        std::span<const std::uint8_t> encoded,
        std::size_t max_output_bytes) {
    if (!is_fast_envelope(encoded) || encoded.size() < kHeaderSize)
        throw std::runtime_error("Compressed workspace signature is invalid");
    const auto method = encoded[4];
    const auto original_u64 = read_u64(encoded, 5);
    const auto payload_u64 = read_u64(encoded, 13);
    const auto expected_crc = read_u32(encoded, 21);
    if (original_u64 > max_output_bytes ||
        original_u64 > std::numeric_limits<std::size_t>::max() ||
        payload_u64 > std::numeric_limits<std::size_t>::max())
        throw std::runtime_error("Compressed workspace exceeds safety limit");
    const auto original_size = static_cast<std::size_t>(original_u64);
    const auto payload_size = static_cast<std::size_t>(payload_u64);
    if (payload_size > encoded.size() - kHeaderSize ||
        payload_size != encoded.size() - kHeaderSize)
        throw std::runtime_error("Compressed workspace length is invalid");
    const auto payload = encoded.subspan(kHeaderSize, payload_size);
    std::vector<std::uint8_t> out;
    out.reserve(original_size);
    if (method == kRaw) {
        if (payload.size() != original_size)
            throw std::runtime_error("Raw workspace length is invalid");
        out.assign(payload.begin(), payload.end());
    } else if (method == kLz || method == kLzBalanced) {
        std::size_t at = 0;
        while (at < payload.size() && out.size() < original_size) {
            const auto control = payload[at++];
            for (unsigned token = 0;
                 token < 8 && out.size() < original_size; ++token) {
                if ((control & (1u << token)) == 0) {
                    if (at >= payload.size())
                        throw std::runtime_error("Compressed workspace is truncated");
                    out.push_back(payload[at++]);
                } else {
                    if (payload.size() - at < 3)
                        throw std::runtime_error("Compressed workspace is truncated");
                    const std::size_t distance =
                        static_cast<std::size_t>(payload[at]) |
                        (static_cast<std::size_t>(payload[at + 1]) << 8);
                    const std::size_t length =
                        static_cast<std::size_t>(payload[at + 2]) + kMinimumMatch;
                    at += 3;
                    const auto actual_distance = distance + 1;
                    if (actual_distance > out.size() ||
                        length > original_size - out.size())
                        throw std::runtime_error("Compressed workspace reference is invalid");
                    for (std::size_t i = 0; i < length; ++i)
                        out.push_back(out[out.size() - actual_distance]);
                }
            }
        }
        if (at != payload.size() || out.size() != original_size)
            throw std::runtime_error("Compressed workspace length is invalid");
    } else {
        throw std::runtime_error("Compressed workspace method is unsupported");
    }
    if (crc32(out) != expected_crc)
        throw std::runtime_error("Compressed workspace integrity check failed");
    return out;
}

FileResult compress_file_fast(
        const std::filesystem::path& input_path,
        const std::filesystem::path& output_path) {
    return compress_file(input_path, output_path, Profile::Fast);
}

FileResult compress_file(
        const std::filesystem::path& input_path,
        const std::filesystem::path& output_path,
        Profile profile) {
    std::error_code size_error;
    const auto input_size = std::filesystem::file_size(input_path, size_error);
    if (size_error) throw std::runtime_error("Input file cannot be measured");
    if (input_size > 2ull * 1024ull * 1024ull * 1024ull)
        throw std::runtime_error("Input file exceeds the 2 GiB safety limit");
    std::ifstream input(input_path, std::ios::binary);
    if (!input) throw std::runtime_error("Input file cannot be opened");
    const auto temporary = temporary_for(output_path);
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("Output file cannot be created");
    FileResult result{input_size, kFileHeaderSize, 0, 0};
    try {
        write_exact(output, kFileMagic.data(), kFileMagic.size());
        write_u64(output, input_size);
        write_u32(output, static_cast<std::uint32_t>(kFileBlockSize));
        std::vector<std::uint8_t> block(kFileBlockSize);
        std::uint64_t remaining = input_size;
        while (remaining != 0) {
            const auto count = static_cast<std::size_t>(
                std::min<std::uint64_t>(remaining, block.size()));
            read_exact(input, block.data(), count);
            const auto bytes =
                std::span<const std::uint8_t>(block.data(), count);
            const auto encoded = profile == Profile::Balanced
                ? encode_balanced(bytes) : encode_fast(bytes);
            write_u32(output, static_cast<std::uint32_t>(count));
            write_u32(output, static_cast<std::uint32_t>(encoded.size()));
            write_exact(output, encoded.data(), encoded.size());
            result.output_bytes += 8 + encoded.size();
            if (encoded.size() > 4 &&
                (encoded[4] == kLz || encoded[4] == kLzBalanced))
                ++result.compressed_blocks;
            else
                ++result.raw_blocks;
            remaining -= count;
        }
        output.flush();
        if (!output) throw std::runtime_error("Compressed file write failed");
        output.close();
        publish_temporary(temporary, output_path);
    } catch (...) {
        output.close();
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        throw;
    }
    return result;
}

FileResult decompress_file_fast(
        const std::filesystem::path& input_path,
        const std::filesystem::path& output_path,
        std::uint64_t max_output_bytes) {
    std::ifstream input(input_path, std::ios::binary);
    if (!input) throw std::runtime_error("Compressed file cannot be opened");
    std::error_code size_error;
    const auto compressed_file_size =
        std::filesystem::file_size(input_path, size_error);
    if (size_error)
        throw std::runtime_error("Compressed file cannot be measured");
    std::array<std::uint8_t, 4> magic{};
    read_exact(input, magic.data(), magic.size());
    if (magic != kFileMagic)
        throw std::runtime_error("This is not a Point PFA1 compressed file");
    const auto original_size = read_stream_u64(input);
    const auto block_size = read_stream_u32(input);
    if (original_size > max_output_bytes)
        throw std::runtime_error("Decompressed file exceeds the safety limit");
    if (block_size == 0 || block_size > kFileBlockSize)
        throw std::runtime_error("Compressed file block size is invalid");
    const auto temporary = temporary_for(output_path);
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("Output file cannot be created");
    FileResult result{compressed_file_size, original_size, 0, 0};
    std::uint64_t processed = 0;
    try {
        while (processed < original_size) {
            const auto plain_size = read_stream_u32(input);
            const auto encoded_size = read_stream_u32(input);
            if (plain_size == 0 || plain_size > block_size ||
                plain_size > original_size - processed ||
                encoded_size < kHeaderSize ||
                encoded_size > plain_size + kHeaderSize + (plain_size / 8 + 2))
                throw std::runtime_error("Compressed file block is invalid");
            std::vector<std::uint8_t> encoded(encoded_size);
            read_exact(input, encoded.data(), encoded.size());
            const auto decoded = decode_fast(encoded, block_size);
            if (decoded.size() != plain_size)
                throw std::runtime_error("Compressed file block length is invalid");
            write_exact(output, decoded.data(), decoded.size());
            processed += decoded.size();
            if (encoded[4] == kLz || encoded[4] == kLzBalanced)
                ++result.compressed_blocks;
            else ++result.raw_blocks;
        }
        if (input.peek() != std::char_traits<char>::eof())
            throw std::runtime_error("Compressed file contains trailing data");
        output.flush();
        if (!output) throw std::runtime_error("Decompressed file write failed");
        output.close();
        publish_temporary(temporary, output_path);
    } catch (...) {
        output.close();
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        throw;
    }
    return result;
}

}  // namespace point::compression
