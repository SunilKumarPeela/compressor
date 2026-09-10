#include "point_fast_compression.h"

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void verify(const std::vector<std::uint8_t>& input) {
    for (const auto profile : {
            point::compression::Profile::Fast,
            point::compression::Profile::Balanced}) {
        const auto encoded = profile == point::compression::Profile::Balanced
            ? point::compression::encode_balanced(input)
            : point::compression::encode_fast(input);
        const auto decoded = point::compression::decode_fast(encoded);
        if (decoded != input) throw std::runtime_error("round-trip mismatch");
    }
}

std::uint32_t test_crc32(const std::vector<std::uint8_t>& data) {
    std::uint32_t crc = 0xffffffffu;
    for (const auto byte : data) {
        crc ^= byte;
        for (int bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^
                (0xedb88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

void append32(std::vector<std::uint8_t>& output, std::uint32_t value) {
    for (unsigned shift = 0; shift < 32; shift += 8)
        output.push_back(static_cast<std::uint8_t>(value >> shift));
}

void append64(std::vector<std::uint8_t>& output, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        output.push_back(static_cast<std::uint8_t>(value >> shift));
}

void expect_decode_failure(std::vector<std::uint8_t> encoded) {
    try {
        (void)point::compression::decode_fast(encoded);
    } catch (const std::runtime_error&) {
        return;
    }
    throw std::runtime_error("malformed compressed input was accepted");
}

}  // namespace

int main() {
    verify({});
    verify({0});
    verify(std::vector<std::uint8_t>(1024 * 1024, 0));
    const std::string csv = "Employee ID,Username,Location,Status\n"
        "00039929,speela,Greeley,Enabled\n";
    std::vector<std::uint8_t> records;
    for (int i = 0; i < 20000; ++i)
        records.insert(records.end(), csv.begin(), csv.end());
    verify(records);
    const auto fast_records = point::compression::encode_fast(records);
    const auto balanced_records = point::compression::encode_balanced(records);
    if (balanced_records.size() > fast_records.size())
        throw std::runtime_error("balanced mode regressed structured data size");

    std::mt19937 generator(42);
    std::vector<std::uint8_t> random(1024 * 1024);
    for (auto& byte : random)
        byte = static_cast<std::uint8_t>(generator());
    const auto random_encoded = point::compression::encode_fast(random);
    verify(random);
    if (random_encoded.size() != random.size() + 25)
        throw std::runtime_error("random input did not use raw fallback");

    for (std::size_t size = 0; size < 10000; size += 97) {
        std::vector<std::uint8_t> fuzz(size);
        for (auto& byte : fuzz)
            byte = static_cast<std::uint8_t>(generator());
        verify(fuzz);
        for (std::size_t i = 3; i < fuzz.size(); i += 5)
            fuzz[i] = fuzz[i - 3];
        verify(fuzz);
    }

    for (const std::size_t size : {
            1024u * 1024u, 2u * 1024u * 1024u + 17u,
            4u * 1024u * 1024u}) {
        std::vector<std::uint8_t> large(size);
        for (auto& byte : large)
            byte = static_cast<std::uint8_t>(generator());
        verify(large);
        for (std::size_t i = 4096; i < large.size(); ++i)
            large[i] = large[i % 4096];
        verify(large);
    }

    // Hand-built valid stream: 65,536 literal bytes followed by one maximum
    // 259-byte match whose encoded distance is exactly the 65,536-byte limit.
    std::vector<std::uint8_t> window(65'536);
    for (std::size_t i = 0; i < window.size(); ++i)
        window[i] = static_cast<std::uint8_t>(i * 131u + i / 251u);
    std::vector<std::uint8_t> expected_window = window;
    expected_window.insert(expected_window.end(), window.begin(),
        window.begin() + 259);
    std::vector<std::uint8_t> payload;
    for (std::size_t at = 0; at < window.size(); at += 8) {
        payload.push_back(0);
        payload.insert(payload.end(), window.begin() + at,
            window.begin() + at + 8);
    }
    payload.push_back(1);
    payload.push_back(0xff);
    payload.push_back(0xff);
    payload.push_back(0xff);
    std::vector<std::uint8_t> boundary{'P', 'F', 'C', '1', 1};
    append64(boundary, expected_window.size());
    append64(boundary, payload.size());
    append32(boundary, test_crc32(expected_window));
    boundary.insert(boundary.end(), payload.begin(), payload.end());
    if (point::compression::decode_fast(boundary) != expected_window)
        throw std::runtime_error("maximum distance/match boundary failed");

    const auto valid = point::compression::encode_fast(records);
    const std::array<std::size_t, 11> corruption_offsets{
            0u, 4u, 5u, 12u, 13u, 20u, 21u, 24u, 25u,
            valid.size() / 2, valid.size() - 1};
    for (const auto offset : corruption_offsets) {
        auto corrupt = valid;
        corrupt[offset] ^= 0x5a;
        expect_decode_failure(std::move(corrupt));
    }
    const std::array<std::size_t, 6> truncated_lengths{
        0u, 1u, 24u, 25u, valid.size() / 2, valid.size() - 1};
    for (const auto length : truncated_lengths)
        expect_decode_failure(std::vector<std::uint8_t>(
            valid.begin(), valid.begin() + length));

    const auto temporary_root = std::filesystem::temp_directory_path() /
        "point-fast-compression-tests-8302";
    std::filesystem::create_directories(temporary_root);
    const auto original_path = temporary_root / "records.csv";
    const auto compressed_path = temporary_root / "records.csv.pfc";
    const auto balanced_path = temporary_root / "records-balanced.csv.pfc";
    const auto restored_path = temporary_root / "records-restored.csv";
    const auto balanced_restored_path =
        temporary_root / "records-balanced-restored.csv";
    {
        std::ofstream output(original_path, std::ios::binary | std::ios::trunc);
        output.write(reinterpret_cast<const char*>(records.data()),
            static_cast<std::streamsize>(records.size()));
    }
    const auto compressed = point::compression::compress_file_fast(
        original_path, compressed_path);
    const auto restored = point::compression::decompress_file_fast(
        compressed_path, restored_path);
    const auto balanced_file = point::compression::compress_file(
        original_path, balanced_path, point::compression::Profile::Balanced);
    (void)point::compression::decompress_file_fast(
        balanced_path, balanced_restored_path);
    if (compressed.compressed_blocks == 0 ||
        restored.output_bytes != records.size())
        throw std::runtime_error("streaming file statistics are invalid");
    if (balanced_file.output_bytes > compressed.output_bytes)
        throw std::runtime_error("balanced streaming output exceeded fast mode");
    std::ifstream restored_input(restored_path, std::ios::binary);
    std::vector<std::uint8_t> restored_bytes(
        std::istreambuf_iterator<char>(restored_input), {});
    if (restored_bytes != records)
        throw std::runtime_error("streaming file round-trip mismatch");
    std::ifstream balanced_input(balanced_restored_path, std::ios::binary);
    std::vector<std::uint8_t> balanced_bytes(
        std::istreambuf_iterator<char>(balanced_input), {});
    if (balanced_bytes != records)
        throw std::runtime_error("balanced streaming round-trip mismatch");
    std::filesystem::remove_all(temporary_root);
    std::cout << "Point Fast Compression tests passed.\n";
}
