#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>

#include <filesystem>
#include <stdexcept>
#include <string>

namespace point {

inline std::filesystem::path install_root() {
    wchar_t executable[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(nullptr, executable, MAX_PATH);
    if (length == 0 || length >= MAX_PATH)
        throw std::runtime_error("Point could not resolve its installation directory");
    return std::filesystem::path(executable).parent_path();
}

inline std::filesystem::path user_data_root() {
    PWSTR local_app_data = nullptr;
    const HRESULT status = SHGetKnownFolderPath(
        FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr, &local_app_data);
    if (FAILED(status) || !local_app_data)
        throw std::runtime_error("Point could not resolve LOCALAPPDATA");
    const std::filesystem::path result =
        std::filesystem::path(local_app_data) / L"Point";
    CoTaskMemFree(local_app_data);
    return result;
}

inline void migrate_legacy_data(const std::filesystem::path& installation,
                                const std::filesystem::path& data_root) {
    if (installation == data_root) return;
    const wchar_t* directories[] = {
        L"Inbox", L"Workspace", L"Exports", L"Logs", L"Fetcher"};
    for (const wchar_t* name : directories) {
        const auto source_root = installation / name;
        const auto destination_root = data_root / name;
        std::error_code error;
        if (!std::filesystem::is_directory(source_root, error) || error)
            continue;
        for (std::filesystem::recursive_directory_iterator iterator(
                 source_root,
                 std::filesystem::directory_options::skip_permission_denied,
                 error), end;
             iterator != end && !error; iterator.increment(error)) {
            if (iterator->is_symlink(error) || error) continue;
            const auto relative =
                std::filesystem::relative(iterator->path(), source_root, error);
            if (error || relative.empty() ||
                relative.native().find(L"..") != std::wstring::npos)
                continue;
            const auto destination = destination_root / relative;
            if (iterator->is_directory(error)) {
                std::filesystem::create_directories(destination, error);
            } else if (iterator->is_regular_file(error) && !error &&
                       !std::filesystem::exists(destination, error)) {
                std::filesystem::create_directories(
                    destination.parent_path(), error);
                if (!error) std::filesystem::copy_file(
                    iterator->path(), destination,
                    std::filesystem::copy_options::none, error);
            }
            error.clear();
        }
    }
}

}  // namespace point
