#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>

#include <string>
#include <vector>

namespace point {

inline std::wstring current_user_sid_string() {
    HANDLE raw_token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token))
        return {};
    DWORD required = 0;
    GetTokenInformation(raw_token, TokenUser, nullptr, 0, &required);
    std::vector<unsigned char> storage(required);
    if (required == 0 || !GetTokenInformation(
            raw_token, TokenUser, storage.data(), required, &required)) {
        CloseHandle(raw_token);
        return {};
    }
    CloseHandle(raw_token);
    const auto* user = reinterpret_cast<const TOKEN_USER*>(storage.data());
    LPWSTR raw_sid = nullptr;
    if (!ConvertSidToStringSidW(user->User.Sid, &raw_sid) || !raw_sid)
        return {};
    const std::wstring sid(raw_sid);
    LocalFree(raw_sid);
    return sid;
}

inline std::wstring inbox_event_name() {
    const auto sid = current_user_sid_string();
    return sid.empty() ? std::wstring{} :
        L"Local\\Point.InboxChanged." + sid;
}

inline HANDLE create_inbox_changed_event() {
    const auto sid = current_user_sid_string();
    if (sid.empty()) return nullptr;
    // Protected DACL: only the signed-in user can open or signal this object.
    const auto descriptor_text = L"D:P(A;;GA;;;" + sid + L")";
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor_text.c_str(), SDDL_REVISION_1, &descriptor, nullptr))
        return nullptr;
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor;
    const auto name = L"Local\\Point.InboxChanged." + sid;
    HANDLE event = CreateEventW(&attributes, TRUE, FALSE, name.c_str());
    LocalFree(descriptor);
    return event;
}

inline bool signal_inbox_changed() {
    const auto name = inbox_event_name();
    if (name.empty()) return false;
    HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, name.c_str());
    if (!event) return false;
    const bool signaled = SetEvent(event) != FALSE;
    CloseHandle(event);
    return signaled;
}

}  // namespace point
