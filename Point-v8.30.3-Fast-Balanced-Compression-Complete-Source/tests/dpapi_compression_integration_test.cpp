#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "point_compliance.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

int main() {
    const auto path = std::filesystem::temp_directory_path() /
        (L"point-dpapi-compression-" + std::to_wstring(GetCurrentProcessId()) +
         L".dat");
    const std::string row =
        "POINT_VIEW_V3\n256\n28\nEmployee ID,Username,Location,Status\n";
    std::string expected;
    expected.reserve(3u * 1024u * 1024u);
    while (expected.size() < 3u * 1024u * 1024u) expected += row;
    try {
        {
            std::ofstream output(path, std::ios::binary | std::ios::trunc);
            output.write(expected.data(),
                static_cast<std::streamsize>(expected.size()));
            if (!output) throw std::runtime_error("test input write failed");
        }
        point::compliance::protect_file_for_current_user(path);
        std::ifstream protected_input(path, std::ios::binary);
        std::vector<unsigned char> protected_bytes(
            std::istreambuf_iterator<char>(protected_input), {});
        if (protected_bytes.empty() ||
            std::search(protected_bytes.begin(), protected_bytes.end(),
                expected.begin(), expected.begin() + 32) != protected_bytes.end())
            throw std::runtime_error("DPAPI file exposed recognizable plaintext");
        const auto restored =
            point::compliance::read_user_protected_file(path);
        if (restored != expected)
            throw std::runtime_error("DPAPI/compression round-trip mismatch");
        std::filesystem::remove(path);
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
        throw;
    }
    std::cout << "Point DPAPI compression integration test passed.\n";
}
