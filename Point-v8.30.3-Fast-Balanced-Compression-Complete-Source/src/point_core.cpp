#include "point_core.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <tuple>
#include <unordered_set>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
constexpr unsigned long point_invalid_file_attributes =
    INVALID_FILE_ATTRIBUTES;
constexpr unsigned long point_file_attribute_reparse_point =
    FILE_ATTRIBUTE_REPARSE_POINT;
#endif

namespace point {
namespace {

bool iequals_ascii(const std::string& a, const std::string& b) {
    return normalize_name(a) == normalize_name(b);
}

std::string audit_safe(std::string value) {
    for (char& ch : value) {
        if (ch == '\r' || ch == '\n' || ch == '\t' ||
            static_cast<unsigned char>(ch) < 0x20) {
            ch = ' ';
        }
    }
    if (value.size() > 2048) value.resize(2048);
    return value;
}

std::string last_audit_hash(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    std::string line;
    std::string last;
    while (std::getline(input, line)) {
        if (!trim(line).empty()) last = std::move(line);
    }
    const auto tab = last.find_last_of('\t');
    return tab == std::string::npos ? std::string(64, '0') :
        last.substr(tab + 1);
}

std::string audit_digest(const std::string& value) {
#ifdef _WIN32
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_size = 0, hash_size = 0, received = 0;
    if (BCryptOpenAlgorithmProvider(
            &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
        BCryptGetProperty(
            algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size),
            &received, 0) < 0 ||
        BCryptGetProperty(
            algorithm, BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&hash_size), sizeof(hash_size),
            &received, 0) < 0) {
        if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
        throw std::runtime_error("Unable to initialize audit SHA-256");
    }
    std::vector<unsigned char> object(object_size);
    std::vector<unsigned char> digest(hash_size);
    const auto create_status = BCryptCreateHash(
        algorithm, &hash, object.data(), object_size, nullptr, 0, 0);
    const auto hash_status = create_status < 0 ? create_status :
        BCryptHashData(
            hash,
            reinterpret_cast<PUCHAR>(
                const_cast<char*>(value.data())),
            static_cast<ULONG>(value.size()), 0);
    const auto finish_status = hash_status < 0 ? hash_status :
        BCryptFinishHash(hash, digest.data(), hash_size, 0);
    if (hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (finish_status < 0)
        throw std::runtime_error("Unable to calculate audit SHA-256");
    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(digest.size() * 2);
    for (unsigned char byte : digest) {
        result.push_back(hex[byte >> 4]);
        result.push_back(hex[byte & 0x0f]);
    }
    return result;
#else
    // Portable tests do not link a platform crypto provider. Production
    // Windows builds always use BCrypt SHA-256 above.
    std::uint64_t hash_value = 1469598103934665603ull;
    for (unsigned char ch : value) {
        hash_value ^= ch;
        hash_value *= 1099511628211ull;
    }
    std::ostringstream out;
    out << std::hex << std::setfill('0') << std::setw(64) << hash_value;
    return out.str();
#endif
}

std::string csv_quote(const std::string& raw) {
    const std::string value = escape_csv_for_spreadsheet(raw);
    if (value.find_first_of(",\"\r\n") == std::string::npos) return value;
    std::string out = "\"";
    for (char ch : value) {
        if (ch == '"') out += "\"\"";
        else out += ch;
    }
    out += '"';
    return out;
}

bool leading_zero_numeric_identity(const std::string& field) {
    return field == "id" || field == "employeeid" ||
           field == "userid";
}

std::string normalized_field_value(
        const std::string& field, const std::string& value) {
    auto normalized = normalize_name(trim(value));
    if (!leading_zero_numeric_identity(field) || normalized.empty() ||
        !std::all_of(
            normalized.begin(), normalized.end(),
            [](unsigned char ch) { return std::isdigit(ch) != 0; })) {
        return normalized;
    }
    const auto first = normalized.find_first_not_of('0');
    return first == std::string::npos ? std::string{"0"} :
        normalized.substr(first);
}

bool is_multi_value_membership_field(const std::string& field) {
    static const std::unordered_set<std::string> fields = {
        "member", "members", "groupmember", "groupmembers",
        "memberlist", "membershiplist", "membernames",
        "membersnames", "memberof"
    };
    return fields.contains(field);
}

std::string index_semantics_field(
        const DataSet& dataset, std::size_t column) {
    if (column < dataset.headers.size()) {
        const auto original = normalize_name(dataset.headers[column]);
        if (is_multi_value_membership_field(original)) return original;
    }
    return column < dataset.canonical_headers.size()
        ? dataset.canonical_headers[column] : std::string{};
}

std::string person_name_key(const std::string& value);

std::vector<std::string> indexed_field_values(
        const std::string& field, const std::string& value) {
    if (!is_multi_value_membership_field(field)) {
        const auto single = normalized_field_value(field, value);
        if (single.empty()) return {};
        std::vector<std::string> values{single};
        if (field == "displayname" || field == "fullname" ||
            field == "name") {
            const auto unordered_name = person_name_key(value);
            if (!unordered_name.empty() && unordered_name != single)
                values.push_back(unordered_name);
        }
        return values;
    }

    // AD/group exports commonly store all members in one cell separated by
    // commas, semicolons, pipes, or line breaks. Index each complete token so
    // a username lookup remains exact and does not degrade into substring
    // matching (for example, "peela" must not match "speela").
    std::vector<std::string> values;
    std::unordered_set<std::string> seen;
    const bool single_comma_name =
        value.find(';') == std::string::npos &&
        value.find('|') == std::string::npos &&
        value.find('\r') == std::string::npos &&
        value.find('\n') == std::string::npos &&
        std::count(value.begin(), value.end(), ',') == 1;
    if (single_comma_name) {
        const auto complete_name = person_name_key(value);
        if (!complete_name.empty() && seen.insert(complete_name).second)
            values.push_back(complete_name);
    }
    std::string token;
    auto emit = [&]() {
        const auto raw_token = token;
        auto normalized = normalized_field_value(field, raw_token);
        token.clear();
        if (normalized.empty()) return;
        if (seen.insert(normalized).second)
            values.push_back(std::move(normalized));
        // Members may contain human display names in either "Last, First"
        // or "First Last" order. Add a complete-token-set key in addition to
        // the literal key. It requires at least two tokens, so a partial first
        // or last name cannot create a membership match.
        const auto unordered_name = person_name_key(raw_token);
        if (!unordered_name.empty() && seen.insert(unordered_name).second)
            values.push_back(unordered_name);
    };
    // A common AD export format is "First, Last; First2, Last2". When a
    // semicolon is present it is the record separator and commas belong to
    // the person's display name. For simple username lists without
    // semicolons, commas remain valid separators.
    const bool semicolon_separated = value.find(';') != std::string::npos;
    for (char ch : value) {
        if (ch == ';' || ch == '|' || ch == '\r' || ch == '\n' ||
            (ch == ',' && !semicolon_separated))
            emit();
        else
            token.push_back(ch);
    }
    emit();
    return values;
}

double overlap_score(const DataSet& left, std::size_t lc,
                     const DataSet& right, std::size_t rc,
                     const std::string& relationship_field) {
    (void)relationship_field;
    const DataSet* smaller = &left;
    const DataSet* larger = &right;
    std::size_t sc = lc, lc2 = rc;
    if (left.rows.size() > right.rows.size()) {
        smaller = &right; larger = &left; sc = rc; lc2 = lc;
    }
    std::unordered_set<std::string> values;
    const std::size_t cap = 50'000;
    for (std::size_t i = 0; i < smaller->rows.size() && i < cap; ++i) {
        if (sc < smaller->rows[i].size()) {
            const auto field = index_semantics_field(*smaller, sc);
            for (auto& value : indexed_field_values(
                     field, smaller->rows[i][sc])) {
                if (!value.empty()) values.insert(std::move(value));
            }
        }
    }
    if (values.empty()) return 0.0;
    std::size_t tested = 0, matched = 0;
    for (std::size_t i = 0; i < larger->rows.size() && i < cap; ++i) {
        if (lc2 >= larger->rows[i].size()) continue;
        const auto field = index_semantics_field(*larger, lc2);
        for (const auto& value : indexed_field_values(
                 field, larger->rows[i][lc2])) {
            if (value.empty()) continue;
            ++tested;
            if (values.contains(value)) ++matched;
        }
    }
    return tested ? static_cast<double>(matched) /
                        static_cast<double>(std::min(tested, values.size()))
                  : 0.0;
}

std::string person_name_key(const std::string& value) {
    std::vector<std::string> tokens;
    std::string token;
    for (unsigned char ch : value) {
        if (std::isalnum(ch)) {
            token.push_back(static_cast<char>(std::tolower(ch)));
        } else if (!token.empty()) {
            tokens.push_back(std::move(token));
            token.clear();
        }
    }
    if (!token.empty()) tokens.push_back(std::move(token));
    if (tokens.size() < 2 || tokens.size() > 12) return {};
    std::sort(tokens.begin(), tokens.end());
    std::string key;
    for (const auto& part : tokens) {
        if (!key.empty()) key.push_back('\x1f');
        key += part;
    }
    return key;
}

int count_source_authority_score(
        const DataSet& dataset,
        const std::string& normalized_field) {
    const auto source = normalize_name(dataset.name);
    auto contains_any = [](const std::string& value,
                           const std::vector<std::string>& terms) {
        return std::any_of(
            terms.begin(), terms.end(),
            [&](const auto& term) {
                return value.find(term) != std::string::npos;
            });
    };

    int score = 0;
    const bool device_security_field = contains_any(
        normalized_field,
        {"encryption", "patch", "crowdstrike", "vulnerability",
         "antivirus", "endpoint", "operatingsystem", "devicestatus",
         "computerstatus"});
    const bool identity_access_field = contains_any(
        normalized_field,
        {"account", "mfa", "password", "locked", "disabled",
         "group", "role", "username", "email", "access"});
    const bool people_field = contains_any(
        normalized_field,
        {"employee", "department", "manager", "location", "jobtitle"});
    const bool ticket_field = contains_any(
        normalized_field,
        {"ticket", "incident", "priority", "resolution"});
    const bool training_field = contains_any(
        normalized_field,
        {"training", "course", "compliance"});

    if (device_security_field) {
        if (source.find("devicesecurity") != std::string::npos)
            score += 500;
        if (contains_any(
                source,
                {"security", "device", "endpoint", "computer"}))
            score += 200;
        if (contains_any(source, {"employee", "people", "hrdata"}))
            score -= 50;
    }
    if (identity_access_field &&
        contains_any(
            source,
            {"identity", "access", "account", "directory", "admanager",
             "user", "group"})) {
        score += 300;
    }
    if (people_field &&
        contains_any(
            source,
            {"employee", "people", "humanresource", "hrdata"})) {
        score += 300;
    }
    if (ticket_field &&
        contains_any(
            source,
            {"ticket", "incident", "helpdesk", "service"})) {
        score += 300;
    }
    if (training_field &&
        contains_any(source, {"training", "course", "compliance"})) {
        score += 300;
    }
    return score;
}

std::optional<std::size_t> authoritative_count_dataset(
        const std::vector<DataSet>& datasets,
        const std::vector<std::size_t>& candidates,
        const std::vector<std::string>& normalized_fields) {
    std::optional<std::size_t> best;
    int best_score = 0;
    bool tied = false;
    for (const auto dataset_id : candidates) {
        int score = 0;
        for (const auto& field : normalized_fields) {
            score += count_source_authority_score(
                datasets[dataset_id], field);
        }
        if (score > best_score) {
            best = dataset_id;
            best_score = score;
            tied = false;
        } else if (score == best_score && score > 0) {
            tied = true;
        }
    }
    return best && !tied ? best : std::nullopt;
}

std::string timestamp_utc() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t time = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &time);
#else
    gmtime_r(&time, &tm);
#endif
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return out.str();
}

bool is_link_like(const std::filesystem::path& path) {
    std::error_code ec;
    if (std::filesystem::is_symlink(path, ec) || ec) return true;
#ifdef _WIN32
    const auto attributes = GetFileAttributesW(path.c_str());
    if (attributes == point_invalid_file_attributes) return true;
    return (attributes & point_file_attribute_reparse_point) != 0;
#else
    return false;
#endif
}

}  // namespace

std::string trim(const std::string& value) {
    auto first = std::find_if_not(value.begin(), value.end(),
        [](unsigned char ch) { return std::isspace(ch) != 0; });
    auto last = std::find_if_not(value.rbegin(), value.rend(),
        [](unsigned char ch) { return std::isspace(ch) != 0; }).base();
    return first < last ? std::string(first, last) : std::string{};
}

std::string normalize_name(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (unsigned char ch : value) {
        if (std::isalnum(ch)) out.push_back(static_cast<char>(std::tolower(ch)));
    }
    return out;
}

namespace {

std::string ascii_lower_trimmed(const std::string& value) {
    auto lowered = trim(value);
    std::transform(
        lowered.begin(), lowered.end(), lowered.begin(),
        [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });
    return lowered;
}

}  // namespace

QueryResult filter_query_result(
        const QueryResult& source,
        std::size_t column,
        RowFilterOperator operation,
        const std::string& value) {
    if (column >= source.headers.size())
        throw std::runtime_error("Filter column is outside the result");
    const auto expected = ascii_lower_trimmed(value);
    if (operation != RowFilterOperator::IsBlank &&
        operation != RowFilterOperator::IsNotBlank && expected.empty()) {
        throw std::runtime_error(
            "Select a populated cell or enter a filter value");
    }

    QueryResult filtered = source;
    filtered.rows.clear();
    for (const auto& row : source.rows) {
        const auto raw = column < row.size() ? row[column] : std::string{};
        const auto comparable = ascii_lower_trimmed(raw);
        bool keep = false;
        switch (operation) {
        case RowFilterOperator::Equals:
            keep = comparable == expected;
            break;
        case RowFilterOperator::Contains:
            keep = comparable.find(expected) != std::string::npos;
            break;
        case RowFilterOperator::StartsWith:
            keep = comparable.rfind(expected, 0) == 0;
            break;
        case RowFilterOperator::EndsWith:
            keep = comparable.size() >= expected.size() &&
                comparable.compare(
                    comparable.size() - expected.size(),
                    expected.size(), expected) == 0;
            break;
        case RowFilterOperator::IsBlank:
            keep = comparable.empty();
            break;
        case RowFilterOperator::IsNotBlank:
            keep = !comparable.empty();
            break;
        }
        if (keep) filtered.rows.push_back(row);
    }
    filtered.explanation =
        "Excel-style local filter on " + source.headers[column] +
        "; " + std::to_string(filtered.rows.size()) + " of " +
        std::to_string(source.rows.size()) + " row(s) retained.";
    return filtered;
}

QueryResult split_query_result_column(
        const QueryResult& source,
        std::size_t column,
        const std::string& delimiter,
        std::size_t maximum_parts) {
    if (column >= source.headers.size())
        throw std::runtime_error("Split column is outside the result");
    if (delimiter.empty() || delimiter.size() > 32)
        throw std::runtime_error(
            "Delimiter must contain between 1 and 32 characters");
    if (maximum_parts < 2 || maximum_parts > 32)
        throw std::runtime_error(
            "Split part limit must be between 2 and 32");

    std::vector<std::vector<std::string>> split_rows;
    split_rows.reserve(source.rows.size());
    std::size_t widest = 0;
    for (const auto& row : source.rows) {
        const auto raw = column < row.size() ? row[column] : std::string{};
        std::vector<std::string> parts;
        std::size_t start = 0;
        while (parts.size() + 1 < maximum_parts) {
            const auto found = raw.find(delimiter, start);
            if (found == std::string::npos) break;
            parts.push_back(trim(raw.substr(start, found - start)));
            start = found + delimiter.size();
        }
        parts.push_back(trim(raw.substr(start)));
        widest = std::max(widest, parts.size());
        split_rows.push_back(std::move(parts));
    }
    widest = std::max<std::size_t>(2, widest);
    if (source.headers.size() + widest > 2'000)
        throw std::runtime_error(
            "Split output would exceed Point's 2,000-column limit");

    QueryResult transformed = source;
    const auto base_header = source.headers[column].empty()
        ? std::string{"Split"} : source.headers[column];
    for (std::size_t part = 0; part < widest; ++part)
        transformed.headers.push_back(
            base_header + " Part " + std::to_string(part + 1));
    for (std::size_t row_id = 0;
         row_id < transformed.rows.size(); ++row_id) {
        auto& output = transformed.rows[row_id];
        output.resize(source.headers.size());
        for (std::size_t part = 0; part < widest; ++part) {
            output.push_back(
                part < split_rows[row_id].size()
                    ? split_rows[row_id][part] : std::string{});
        }
    }
    transformed.explanation =
        "Split " + source.headers[column] + " using delimiter '" +
        delimiter + "' into " + std::to_string(widest) +
        " appended column(s); original values retained.";
    return transformed;
}

std::optional<std::string> remove_text_pattern(
        const std::string& value,
        const std::string& selected_text,
        TextMatchPosition position) {
    if (selected_text.empty() || selected_text.size() > 512)
        return std::nullopt;
    auto comparable = value;
    std::transform(
        comparable.begin(), comparable.end(), comparable.begin(),
        [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });
    auto token = selected_text;
    std::transform(
        token.begin(), token.end(), token.begin(),
        [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });

    std::size_t match = std::string::npos;
    switch (position) {
    case TextMatchPosition::Prefix:
        if (comparable.rfind(token, 0) == 0) match = 0;
        break;
    case TextMatchPosition::Suffix:
        if (comparable.size() >= token.size() &&
            comparable.compare(
                comparable.size() - token.size(), token.size(), token) == 0) {
            match = comparable.size() - token.size();
        }
        break;
    case TextMatchPosition::Anywhere:
        match = comparable.find(token);
        break;
    }
    if (match == std::string::npos || match + selected_text.size() > value.size())
        return std::nullopt;
    auto transformed = value;
    transformed.erase(match, selected_text.size());
    return transformed;
}

std::optional<std::string> keep_text_side(
        const std::string& value,
        const std::string& delimiter,
        TextSide side) {
    if (delimiter.empty() || delimiter.size() > 32)
        return std::nullopt;
    const auto found = value.find(delimiter);
    if (found == std::string::npos) return std::nullopt;
    if (side == TextSide::Left)
        return trim(value.substr(0, found));
    return trim(value.substr(found + delimiter.size()));
}

std::string escape_csv_for_spreadsheet(const std::string& value) {
    const auto pos = value.find_first_not_of(" \t\r\n");
    if (pos != std::string::npos &&
        (value[pos] == '=' || value[pos] == '+' ||
         value[pos] == '-' || value[pos] == '@')) {
        return "'" + value;
    }
    return value;
}

bool looks_like_payment_card_number(const std::string& value) {
    std::string digits;
    digits.reserve(value.size());
    for (unsigned char ch : value) {
        if (std::isdigit(ch)) digits.push_back(static_cast<char>(ch));
        else if (ch != ' ' && ch != '-') return false;
    }
    if (digits.size() < 13 || digits.size() > 19) return false;
    int sum = 0;
    bool double_digit = false;
    for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
        int digit = *it - '0';
        if (double_digit) {
            digit *= 2;
            if (digit > 9) digit -= 9;
        }
        sum += digit;
        double_digit = !double_digit;
    }
    return sum % 10 == 0;
}

bool is_highly_sensitive_field(const std::string& header) {
    const auto name = normalize_name(header);
    static const std::unordered_set<std::string> sensitive = {
        "password", "passwordhash", "secret", "secretkey", "apikey",
        "accesstoken", "refreshtoken", "privatekey", "socialsecuritynumber",
        "ssn", "taxid", "nationalid", "cardnumber", "creditcardnumber",
        "debitcardnumber", "pan", "cvv", "cvc", "securitycode"
    };
    return sensitive.contains(name);
}

std::string mask_sensitive_value(const std::string& value) {
    if (value.empty()) return {};
    if (value.size() <= 4) return std::string(value.size(), '*');
    return std::string(value.size() - 4, '*') + value.substr(value.size() - 4);
}

Engine::Engine(Limits limits) : limits_(limits) {}

Engine::Engine(const Engine& other)
    : limits_(other.limits_),
      datasets_(other.datasets_),
      relationships_(other.relationships_),
      issues_(other.issues_),
      field_synonyms_(other.field_synonyms_),
      user_relationships_(other.user_relationships_),
      field_aliases_(other.field_aliases_),
      canonical_display_names_(other.canonical_display_names_) {}

std::string Engine::canonical_field_name(const std::string& field) const {
    const auto normalized = normalize_name(field);
    const auto found = field_aliases_.find(normalized);
    return found == field_aliases_.end() ? normalized : found->second;
}

void Engine::set_field_synonyms(
        const std::vector<FieldSynonymGroup>& groups) {
    if (groups.size() > 64)
        throw std::runtime_error("At most 64 field synonym groups are supported");

    std::unordered_map<std::string, std::string> aliases;
    std::unordered_map<std::string, std::string> display_names;
    std::unordered_set<std::string> canonical_fields;
    std::vector<FieldSynonymGroup> validated;
    for (const auto& group : groups) {
        const auto canonical_display = trim(group.canonical_field);
        const auto canonical = normalize_name(canonical_display);
        if (canonical.empty())
            throw std::runtime_error("A synonym group has a blank canonical field");
        if (!canonical_fields.insert(canonical).second)
            throw std::runtime_error(
                "Canonical field '" + canonical_display +
                "' is listed more than once");
        if (group.synonyms.size() > 64)
            throw std::runtime_error(
                "A synonym group cannot contain more than 64 names");

        FieldSynonymGroup clean{canonical_display, {}};
        display_names[canonical] = canonical_display;
        auto register_name = [&](const std::string& raw, bool synonym) {
            const auto display = trim(raw);
            const auto normalized = normalize_name(display);
            if (normalized.empty() || display.size() > limits_.max_header_bytes)
                throw std::runtime_error("A field synonym is blank or oversized");
            const auto existing = aliases.find(normalized);
            if (existing != aliases.end() && existing->second != canonical)
                throw std::runtime_error(
                    "Field name '" + display +
                    "' belongs to more than one canonical field");
            aliases[normalized] = canonical;
            if (synonym && normalized != canonical &&
                std::none_of(clean.synonyms.begin(), clean.synonyms.end(),
                    [&](const auto& value) {
                        return normalize_name(value) == normalized;
                    })) {
                clean.synonyms.push_back(display);
            }
        };
        register_name(canonical_display, false);
        for (const auto& synonym : group.synonyms)
            register_name(synonym, true);
        validated.push_back(std::move(clean));
    }

    field_synonyms_ = std::move(validated);
    field_aliases_ = std::move(aliases);
    canonical_display_names_ = std::move(display_names);
    rebuild_dataset_field_indexes();
    exact_value_indexes_.clear();
    discover_relationships();
}

void Engine::set_user_relationships(
        const std::vector<UserRelationshipRule>& rules) {
    std::vector<UserRelationshipRule> validated;
    validated.reserve(rules.size());
    std::set<std::pair<std::string, std::string>> seen;
    for (auto rule : rules) {
        rule.left_field = trim(rule.left_field);
        rule.right_field = trim(rule.right_field);
        if (rule.left_field.empty() || rule.right_field.empty())
            throw std::runtime_error(
                "Relationship fields cannot be blank");
        if (rule.delimiter.empty() || rule.delimiter.size() > 8)
            throw std::runtime_error(
                "Relationship delimiter must contain 1-8 characters");
        if (rule.minimum_overlap < 0.05 || rule.minimum_overlap > 1.0)
            throw std::runtime_error(
                "Relationship minimum overlap must be between 0.05 and 1.0");
        auto left = canonical_field_name(rule.left_field);
        auto right = canonical_field_name(rule.right_field);
        if (left == right &&
            rule.mode != RelationshipMatchMode::Equivalent)
            throw std::runtime_error(
                "A list relationship requires two distinct canonical fields");
        auto ordered = std::minmax(left, right);
        if (!seen.insert({ordered.first, ordered.second}).second)
            throw std::runtime_error(
                "The same relationship field pair was configured twice");
        validated.push_back(std::move(rule));
    }
    user_relationships_ = std::move(validated);
    exact_value_indexes_.clear();
    discover_relationships();
}

void Engine::rebuild_dataset_field_indexes() {
    for (auto& dataset : datasets_) {
        dataset.normalized_header_index.clear();
        dataset.normalized_header_index.reserve(dataset.headers.size());
        dataset.canonical_headers.clear();
        dataset.canonical_headers.reserve(dataset.headers.size());
        for (std::size_t column = 0; column < dataset.headers.size(); ++column) {
            const auto key = canonical_field_name(dataset.headers[column]);
            const auto existing = dataset.normalized_header_index.find(key);
            if (existing != dataset.normalized_header_index.end() &&
                existing->second != column) {
                throw std::runtime_error(
                    "Synonym mapping makes two columns equivalent in " +
                    dataset.name + ": " + dataset.headers[existing->second] +
                    " and " + dataset.headers[column]);
            }
            dataset.normalized_header_index[key] = column;
            dataset.canonical_headers.push_back(key);
        }
    }
}

const Engine::ExactValueIndex& Engine::exact_value_index(
        std::size_t dataset_id, std::size_t column) const {
    const auto cache_key =
        (static_cast<std::uint64_t>(dataset_id) << 32) |
        static_cast<std::uint64_t>(column);
    const auto cached = exact_value_indexes_.find(cache_key);
    if (cached != exact_value_indexes_.end())
        return cached->second;

    ExactValueIndex index;
    const auto& dataset = datasets_.at(dataset_id);
    // Estimate cardinality from a bounded sample. Reserving only 131k buckets
    // made high-cardinality million-row columns repeatedly rehash, while
    // reserving every row wastes memory for status/group columns.
    const std::size_t sample_size =
        std::min<std::size_t>(dataset.rows.size(), 4'096);
    std::unordered_set<std::string> sampled_values;
    sampled_values.reserve(sample_size);
    const auto indexed_field = index_semantics_field(dataset, column);
    for (std::size_t row_id = 0; row_id < sample_size; ++row_id) {
        const auto& row = dataset.rows[row_id];
        if (column >= row.size()) continue;
        for (auto& value : indexed_values_for(
                 indexed_field, row[column])) {
            if (!value.empty()) sampled_values.insert(std::move(value));
        }
    }
    if (sample_size != 0) {
        const double distinct_ratio =
            static_cast<double>(sampled_values.size()) /
            static_cast<double>(sample_size);
        const auto estimated = static_cast<std::size_t>(
            static_cast<double>(dataset.rows.size()) * distinct_ratio * 1.10);
        index.reserve(std::clamp<std::size_t>(
            estimated, sampled_values.size(), dataset.rows.size()));
    }
    for (std::size_t row_id = 0;
         row_id < dataset.rows.size(); ++row_id) {
        const auto& row = dataset.rows[row_id];
        if (column >= row.size()) continue;
        for (const auto& value : indexed_values_for(
                 indexed_field, row[column])) {
            if (!value.empty()) index[value].push_back(row_id);
        }
    }
    return exact_value_indexes_
        .emplace(cache_key, std::move(index))
        .first->second;
}

std::vector<std::string> Engine::indexed_values_for(
        const std::string& field, const std::string& value) const {
    for (const auto& rule : user_relationships_) {
        if (!rule.enabled || rule.mode == RelationshipMatchMode::Equivalent)
            continue;
        const auto left = canonical_field_name(rule.left_field);
        const auto right = canonical_field_name(rule.right_field);
        const bool is_list =
            (rule.mode == RelationshipMatchMode::LeftListContainsRight &&
             field == left) ||
            (rule.mode == RelationshipMatchMode::RightListContainsLeft &&
             field == right);
        if (!is_list) continue;
        std::vector<std::string> values;
        std::unordered_set<std::string> seen;
        std::size_t start = 0;
        while (start <= value.size()) {
            const auto found = value.find(rule.delimiter, start);
            const auto raw = value.substr(
                start, found == std::string::npos
                    ? std::string::npos : found - start);
            auto normalized = normalized_field_value(field, raw);
            if (!normalized.empty() && seen.insert(normalized).second)
                values.push_back(std::move(normalized));
            if (found == std::string::npos) break;
            start = found + rule.delimiter.size();
        }
        return values;
    }
    return indexed_field_values(field, value);
}

std::string Engine::indexed_value_key(
        std::size_t dataset_id, std::size_t column,
        const std::string& value) const {
    const auto& dataset = datasets_.at(dataset_id);
    if (column >= dataset.canonical_headers.size()) return {};
    return normalized_field_value(dataset.canonical_headers[column], value);
}

bool Engine::indexed_unique_column(
        std::size_t dataset_id, std::size_t column) const {
    const auto& index = exact_value_index(dataset_id, column);
    return !index.empty() &&
        std::all_of(
            index.begin(), index.end(),
            [](const auto& entry) {
                return entry.second.size() == 1;
            });
}

DataSet Engine::parse_csv(const std::filesystem::path& path) const {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec) || ec)
        throw std::runtime_error("Not a regular file");
    if (is_link_like(path))
        throw std::runtime_error("Links are not accepted");
    const auto size = std::filesystem::file_size(path, ec);
    if (ec || size > limits_.max_file_bytes)
        throw std::runtime_error("File exceeds the configured size limit");

    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("Unable to open file read-only");

    DataSet set;
    set.path = path;
    set.name = path.filename().string();
    set.source_size = size;
    const auto modified = std::filesystem::last_write_time(path, ec);
    if (!ec)
        set.source_modified = static_cast<std::int64_t>(
            modified.time_since_epoch().count());
    std::vector<std::string> record;
    std::string cell;
    bool quoted = false;
    bool at_start = true;
    std::size_t logical_rows = 0;

    auto push_cell = [&]() {
        if (cell.size() > limits_.max_cell_bytes)
            throw std::runtime_error("Cell exceeds the configured size limit");
        record.push_back(std::move(cell));
        cell.clear();
        if (record.size() > limits_.max_columns)
            throw std::runtime_error("Column count exceeds the configured limit");
    };
    auto push_record = [&]() {
        push_cell();
        bool empty = std::all_of(record.begin(), record.end(),
            [](const std::string& s) { return trim(s).empty(); });
        if (!empty) {
            if (set.headers.empty()) {
                set.headers = std::move(record);
                if (set.headers.size() < 1)
                    throw std::runtime_error("Missing header row");
                std::unordered_set<std::string> names;
                for (std::size_t i = 0; i < set.headers.size(); ++i) {
                    set.headers[i] = trim(set.headers[i]);
                    if (i == 0 && set.headers[i].size() >= 3 &&
                        static_cast<unsigned char>(set.headers[i][0]) == 0xEF &&
                        static_cast<unsigned char>(set.headers[i][1]) == 0xBB &&
                        static_cast<unsigned char>(set.headers[i][2]) == 0xBF)
                        set.headers[i].erase(0, 3);
                    if (set.headers[i].size() > limits_.max_header_bytes)
                        throw std::runtime_error("Oversized header");
                    if (set.headers[i].empty()) {
                        const std::string base =
                            "Unnamed Column " + std::to_string(i + 1);
                        set.headers[i] = base;
                        std::size_t suffix = 2;
                        while (names.contains(normalize_name(set.headers[i])))
                            set.headers[i] = base + " (" +
                                std::to_string(suffix++) + ")";
                    }
                    const auto normalized = normalize_name(set.headers[i]);
                    if (normalized.empty() || !names.insert(normalized).second)
                        throw std::runtime_error("Duplicate or invalid header");
                    set.normalized_header_index[normalized] = i;
                }
            } else {
                if (record.size() != set.headers.size())
                    throw std::runtime_error("Record has a different column count");
                set.rows.push_back(std::move(record));
                if (++logical_rows > limits_.max_rows)
                    throw std::runtime_error("Row count exceeds the configured limit");
            }
        }
        record.clear();
    };

    char ch;
    while (input.get(ch)) {
        if (ch == '\0') throw std::runtime_error("Null byte detected");
        if (quoted) {
            if (ch == '"') {
                if (input.peek() == '"') { input.get(ch); cell.push_back('"'); }
                else quoted = false;
            } else {
                cell.push_back(ch);
            }
        } else if (ch == '"' && at_start) {
            quoted = true;
        } else if (ch == ',') {
            push_cell();
            at_start = true;
            continue;
        } else if (ch == '\n') {
            if (!cell.empty() && cell.back() == '\r') cell.pop_back();
            push_record();
            at_start = true;
            continue;
        } else {
            if (ch == '"' && !cell.empty())
                throw std::runtime_error("Unexpected quote in unquoted field");
            cell.push_back(ch);
        }
        at_start = false;
        if (cell.size() > limits_.max_cell_bytes)
            throw std::runtime_error("Cell exceeds the configured size limit");
    }
    if (quoted) throw std::runtime_error("Unterminated quoted field");
    if (!cell.empty() || !record.empty()) push_record();
    if (set.headers.empty()) throw std::runtime_error("No header row found");
    return set;
}

void Engine::load_inbox(const std::filesystem::path& inbox) {
    std::vector<std::filesystem::path> files;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(inbox, ec)) {
        if (ec) break;
        const auto ext = entry.path().extension().string();
        if (iequals_ascii(ext, ".csv")) files.push_back(entry.path());
    }
    if (ec) throw std::runtime_error("Unable to enumerate Inbox");
    load_files(files);
}

void Engine::load_files(
        const std::vector<std::filesystem::path>& files) {
    load_files_incremental(files, nullptr);
}

void Engine::load_files_incremental(
        const std::vector<std::filesystem::path>& files,
        const Engine* previous,
        const std::function<void(
            std::size_t, std::size_t,
            const std::filesystem::path&, bool)>& progress,
        const std::function<bool()>& cancelled) {
    std::vector<DataSet> staged;
    std::vector<ImportIssue> staged_issues;
    std::size_t reused_count = 0;
    for (std::size_t file_index = 0; file_index < files.size(); ++file_index) {
        const auto& path = files[file_index];
        if (cancelled && cancelled())
            throw std::runtime_error("Refresh cancelled");
        if (!iequals_ascii(path.extension().string(), ".csv")) continue;
        try {
            bool reused = false;
            std::error_code error;
            const auto size = std::filesystem::file_size(path, error);
            const auto modified = std::filesystem::last_write_time(path, error);
            const auto ticks = error ? 0 : static_cast<std::int64_t>(
                modified.time_since_epoch().count());
            if (previous && !error) {
                const auto found = std::find_if(
                    previous->datasets_.begin(), previous->datasets_.end(),
                    [&](const DataSet& candidate) {
                        return candidate.path == path &&
                               candidate.source_size == size &&
                               candidate.source_modified == ticks;
                    });
                if (found != previous->datasets_.end()) {
                    staged.push_back(*found);
                    reused = true;
                    ++reused_count;
                }
            }
            if (!reused) staged.push_back(parse_csv(path));
            if (progress)
                progress(file_index + 1, files.size(), path, reused);
        } catch (const std::exception& ex) {
            staged_issues.push_back({path, ex.what()});
        }
    }
    std::sort(staged.begin(), staged.end(),
              [](const DataSet& a, const DataSet& b) { return a.name < b.name; });
    datasets_ = std::move(staged);
    issues_ = std::move(staged_issues);
    rebuild_dataset_field_indexes();
    // Unchanged refreshes keep the already validated relationship graph and
    // any exact-value indexes that searches built on demand. Both engines use
    // the same stable dataset ordering, so their dataset/column keys remain
    // valid. This avoids expensive relationship discovery on every Refresh.
    if (previous && reused_count == datasets_.size() &&
        datasets_.size() == previous->datasets_.size()) {
        relationships_ = previous->relationships_;
        exact_value_indexes_ = previous->exact_value_indexes_;
        return;
    }
    exact_value_indexes_.clear();
    discover_relationships();
}

void Engine::discover_relationships() {
    relationships_.clear();
    auto identity_family = [](const std::string& field) {
        static const std::unordered_set<std::string> account_names = {
            "username", "samaccountname", "accountname", "loginname",
            "userlogonname", "networkid"
        };
        return account_names.contains(field)
            ? std::string{"accountname"} : std::string{};
    };
    auto ad_relationship_family = [](const std::string& field) {
        if (field == "memberof" || field == "groupname")
            return std::string{"adgroupname"};
        if (field == "membernames" || field == "membersnames" ||
            field == "displayname" || field == "fullname")
            return std::string{"persondisplayname"};
        if (field == "members" || field == "member" ||
            field == "distinguishedname")
            return std::string{"addistinguishedname"};
        return std::string{};
    };
    for (std::size_t a = 0; a < datasets_.size(); ++a) {
        for (std::size_t b = a + 1; b < datasets_.size(); ++b) {
            for (const auto& [name, ac] : datasets_[a].normalized_header_index) {
                const auto found = datasets_[b].normalized_header_index.find(name);
                if (found == datasets_[b].normalized_header_index.end()) continue;
                const auto bc = found->second;
                const bool left_unique =
                    indexed_unique_column(a, ac);
                const bool right_unique =
                    indexed_unique_column(b, bc);
                // Any equivalent field can form a controlled catalog-style
                // relationship when at least one side is unique. The overlap
                // threshold below must also pass, while the many-to-many
                // guard remains mandatory.
                if (!left_unique && !right_unique) {
                    continue;
                }
                const double overlap = overlap_score(
                    datasets_[a], ac, datasets_[b], bc, name);
                if (overlap < 0.50) continue;
                relationships_.push_back({
                    a, b, ac, bc, std::min(1.0, 0.75 + overlap * 0.25),
                    left_unique, right_unique
                });
            }
            // AD and identity reports frequently use User Name in one file
            // and SAM Account Name in another. They are safe equivalent join
            // keys when their values overlap and at least one side is unique,
            // but remain separately displayable output fields.
            for (const auto& [left_name, left_column] :
                 datasets_[a].normalized_header_index) {
                const auto family = identity_family(left_name);
                if (family.empty()) continue;
                for (const auto& [right_name, right_column] :
                     datasets_[b].normalized_header_index) {
                    if (left_name == right_name ||
                        identity_family(right_name) != family) {
                        continue;
                    }
                    const bool already_linked = std::any_of(
                        relationships_.begin(), relationships_.end(),
                        [&](const auto& relationship) {
                            return relationship.left_dataset == a &&
                                   relationship.right_dataset == b &&
                                   relationship.left_column == left_column &&
                                   relationship.right_column == right_column;
                        });
                    if (already_linked) continue;
                    const bool left_unique =
                        indexed_unique_column(a, left_column);
                    const bool right_unique =
                        indexed_unique_column(b, right_column);
                    if (!left_unique && !right_unique) continue;
                    const double overlap = overlap_score(
                        datasets_[a], left_column, datasets_[b],
                        right_column, family);
                    if (overlap < 0.50) continue;
                    relationships_.push_back({
                        a, b, left_column, right_column,
                        std::min(1.0, 0.75 + overlap * 0.25),
                        left_unique, right_unique
                    });
                }
            }
            // ADManager user and group reports describe the same relationship
            // using different headings. Link only these explicit semantic
            // pairs, require meaningful value overlap, and retain the normal
            // uniqueness guard to avoid unsafe many-to-many joins.
            for (const auto& [left_name, left_column] :
                 datasets_[a].normalized_header_index) {
                const auto family = ad_relationship_family(left_name);
                if (family.empty()) continue;
                for (const auto& [right_name, right_column] :
                     datasets_[b].normalized_header_index) {
                    if (left_name == right_name ||
                        ad_relationship_family(right_name) != family)
                        continue;
                    const bool already_linked = std::any_of(
                        relationships_.begin(), relationships_.end(),
                        [&](const auto& relationship) {
                            return relationship.left_dataset == a &&
                                   relationship.right_dataset == b &&
                                   relationship.left_column == left_column &&
                                   relationship.right_column == right_column;
                        });
                    if (already_linked) continue;
                    const bool left_unique =
                        indexed_unique_column(a, left_column);
                    const bool right_unique =
                        indexed_unique_column(b, right_column);
                    if (!left_unique && !right_unique) continue;
                    const double overlap = overlap_score(
                        datasets_[a], left_column, datasets_[b],
                        right_column, family);
                    if (overlap < 0.20) continue;
                    relationships_.push_back({
                        a, b, left_column, right_column,
                        std::min(1.0, 0.80 + overlap * 0.20),
                        left_unique, right_unique
                    });
                }
            }
            // Some ADManager group exports label a semicolon-delimited list
            // of plain display names simply as "Members" rather than
            // "Members' Names".  Other exports use the same heading for
            // distinguished names, so do not hard-code one meaning. Add the
            // Display Name/Full Name relationship only when exact split-token
            // overlap proves that this workbook contains plain names.
            auto is_flexible_members = [](const std::string& field) {
                return field == "members" || field == "member";
            };
            auto is_person_display = [](const std::string& field) {
                return field == "displayname" || field == "fullname";
            };
            // Inspect original column positions rather than the one-column-
            // per-canonical-name map. A group report can contain both its own
            // Display Name and a Members column that the user mapped as a
            // Display Name synonym; both must remain independently addressable.
            for (std::size_t left_column = 0;
                 left_column < datasets_[a].headers.size(); ++left_column) {
                const auto left_name = normalize_name(
                    datasets_[a].headers[left_column]);
                for (std::size_t right_column = 0;
                     right_column < datasets_[b].headers.size();
                     ++right_column) {
                    const auto right_name = normalize_name(
                        datasets_[b].headers[right_column]);
                    const bool compatible =
                        (is_flexible_members(left_name) &&
                         is_person_display(right_name)) ||
                        (is_person_display(left_name) &&
                         is_flexible_members(right_name));
                    if (!compatible) continue;
                    const bool already_linked = std::any_of(
                        relationships_.begin(), relationships_.end(),
                        [&](const auto& relationship) {
                            return relationship.left_dataset == a &&
                                   relationship.right_dataset == b &&
                                   relationship.left_column == left_column &&
                                   relationship.right_column == right_column;
                        });
                    if (already_linked) continue;
                    const bool left_unique =
                        indexed_unique_column(a, left_column);
                    const bool right_unique =
                        indexed_unique_column(b, right_column);
                    if (!left_unique && !right_unique) continue;
                    const double overlap = overlap_score(
                        datasets_[a], left_column, datasets_[b],
                        right_column, "persondisplayname");
                    if (overlap < 0.20) continue;
                    relationships_.push_back({
                        a, b, left_column, right_column,
                        std::min(1.0, 0.80 + overlap * 0.20),
                        left_unique, right_unique
                    });
                }
            }
            for (const auto& rule : user_relationships_) {
                if (!rule.enabled) continue;
                const auto configured_left =
                    canonical_field_name(rule.left_field);
                const auto configured_right =
                    canonical_field_name(rule.right_field);
                auto add_configured = [&](const std::string& left_field,
                                          const std::string& right_field) {
                    const auto left = datasets_[a].normalized_header_index.find(
                        left_field);
                    const auto right = datasets_[b].normalized_header_index.find(
                        right_field);
                    if (left == datasets_[a].normalized_header_index.end() ||
                        right == datasets_[b].normalized_header_index.end())
                        return;
                    const bool duplicate = std::any_of(
                        relationships_.begin(), relationships_.end(),
                        [&](const auto& relationship) {
                            return relationship.left_dataset == a &&
                                   relationship.right_dataset == b &&
                                   relationship.left_column == left->second &&
                                   relationship.right_column == right->second;
                        });
                    if (duplicate) return;
                    const auto& left_index = exact_value_index(a, left->second);
                    const auto& right_index = exact_value_index(b, right->second);
                    if (left_index.empty() || right_index.empty()) return;
                    const auto& smaller = left_index.size() <= right_index.size()
                        ? left_index : right_index;
                    const auto& larger = left_index.size() <= right_index.size()
                        ? right_index : left_index;
                    std::size_t common = 0;
                    for (const auto& [key, rows] : smaller) {
                        (void)rows;
                        if (larger.contains(key)) ++common;
                    }
                    const double overlap = static_cast<double>(common) /
                        static_cast<double>(smaller.size());
                    if (overlap < rule.minimum_overlap) return;
                    const bool left_unique = indexed_unique_column(a, left->second);
                    const bool right_unique = indexed_unique_column(b, right->second);
                    if (!left_unique && !right_unique)
                        return;
                    relationships_.push_back({
                        a, b, left->second, right->second,
                        std::min(1.0, 0.80 + overlap * 0.20),
                        left_unique, right_unique
                    });
                };
                add_configured(configured_left, configured_right);
                add_configured(configured_right, configured_left);
            }
        }
    }
}

std::vector<std::string> Engine::all_fields() const {
    std::unordered_map<std::string, std::string> unique;
    for (const auto& set : datasets_) {
        for (const auto& header : set.headers) {
            const auto canonical = canonical_field_name(header);
            const auto display = canonical_display_names_.find(canonical);
            unique.try_emplace(
                canonical,
                display == canonical_display_names_.end()
                    ? header : display->second);
        }
    }
    std::vector<std::string> fields;
    fields.reserve(unique.size());
    for (const auto& [_, field] : unique) fields.push_back(field);
    std::sort(fields.begin(), fields.end());
    return fields;
}

std::vector<std::string> Engine::values_for_field(
        const std::string& field,
        const std::string& prefix,
        std::size_t limit) const {
    std::vector<std::string> values;
    if (limit == 0) return values;
    const auto normalized_field = canonical_field_name(field);
    const auto normalized_prefix = normalize_name(prefix);
    std::unordered_set<std::string> seen;
    for (const auto& set : datasets_) {
        const auto column = set.normalized_header_index.find(normalized_field);
        if (column == set.normalized_header_index.end()) continue;
        for (const auto& row : set.rows) {
            if (column->second >= row.size()) continue;
            const auto value = trim(row[column->second]);
            if (value.empty()) continue;
            const auto comparable = normalize_name(value);
            if (!normalized_prefix.empty() &&
                comparable.rfind(normalized_prefix, 0) != 0)
                continue;
            if (seen.insert(comparable).second) values.push_back(value);
            if (values.size() >= limit) break;
        }
        if (values.size() >= limit) break;
    }
    std::sort(values.begin(), values.end());
    return values;
}

IdentityResolution Engine::resolve_identity_from_name(
        const std::string& target_field,
        const std::string& entered_name) const {
    const auto target = canonical_field_name(target_field);
    static const std::unordered_set<std::string> supported_targets = {
        "employeeid", "username", "samaccountname", "email", "userid",
        "userprincipalname"
    };
    if (!supported_targets.contains(target)) return {};

    const auto entered = trim(entered_name);
    const auto requested_name = person_name_key(entered);
    const auto requested_single = normalize_name(entered);
    const bool single_name_token = requested_name.empty() &&
        !requested_single.empty() &&
        std::all_of(
            requested_single.begin(), requested_single.end(),
            [](unsigned char ch) { return std::isalpha(ch) != 0; });
    if (requested_name.empty() && !single_name_token)
        return {IdentityResolutionStatus::NoMatch, {}, 0};

    static const std::vector<std::string> direct_name_fields = {
        "displayname", "fullname", "name"
    };
    static const std::vector<std::string> first_name_fields = {
        "firstname", "givenname"
    };
    static const std::vector<std::string> last_name_fields = {
        "lastname", "surname"
    };
    static const std::vector<std::string> bridge_fields = {
        "employeeid", "username", "samaccountname", "email", "userid",
        "userprincipalname", "computerid", "computername"
    };

    std::set<std::string> resolved_values;
    std::set<std::pair<std::string, std::string>> bridges;
    std::size_t matched_rows = 0;
    for (const auto& dataset : datasets_) {
        std::vector<std::size_t> direct_columns;
        for (const auto& name_field : direct_name_fields) {
            const auto found = dataset.normalized_header_index.find(name_field);
            if (found != dataset.normalized_header_index.end())
                direct_columns.push_back(found->second);
        }
        std::vector<std::pair<std::size_t, std::size_t>> split_columns;
        for (const auto& first_field : first_name_fields) {
            const auto first =
                dataset.normalized_header_index.find(first_field);
            if (first == dataset.normalized_header_index.end()) continue;
            for (const auto& last_field : last_name_fields) {
                const auto last =
                    dataset.normalized_header_index.find(last_field);
                if (last != dataset.normalized_header_index.end())
                    split_columns.push_back({first->second, last->second});
            }
        }
        if (direct_columns.empty() && split_columns.empty()) continue;

        const auto target_column =
            dataset.normalized_header_index.find(target);
        for (const auto& row : dataset.rows) {
            bool matches = false;
            for (const auto column : direct_columns) {
                if (column < row.size() &&
                    ((!requested_name.empty() &&
                      person_name_key(row[column]) == requested_name) ||
                     (single_name_token &&
                      normalize_name(row[column]) == requested_single))) {
                    matches = true;
                    break;
                }
            }
            if (!matches) {
                for (const auto& [first, last] : split_columns) {
                    if (first >= row.size() || last >= row.size()) continue;
                    const bool full_name_match = !requested_name.empty() &&
                        person_name_key(row[first] + " " + row[last]) ==
                            requested_name;
                    const bool component_match = single_name_token &&
                        (normalize_name(row[first]) == requested_single ||
                         normalize_name(row[last]) == requested_single);
                    if (full_name_match || component_match) {
                        matches = true;
                        break;
                    }
                }
            }
            if (!matches) continue;
            if (++matched_rows > 100)
                return {IdentityResolutionStatus::Ambiguous, {}, matched_rows};
            if (target_column != dataset.normalized_header_index.end() &&
                target_column->second < row.size()) {
                const auto value = trim(row[target_column->second]);
                if (!value.empty()) resolved_values.insert(value);
            }
            for (const auto& bridge : bridge_fields) {
                const auto column =
                    dataset.normalized_header_index.find(bridge);
                if (column == dataset.normalized_header_index.end() ||
                    column->second >= row.size()) continue;
                const auto value = trim(row[column->second]);
                if (!value.empty()) bridges.insert({bridge, value});
            }
        }
    }

    for (const auto& [bridge_field, bridge_value] : bridges) {
        if (resolved_values.size() > 1) break;
        try {
            QueryRequest request;
            request.lookup_field = bridge_field;
            request.lookup_value = bridge_value;
            request.output_fields = {target_field};
            const auto result = query(request);
            for (const auto& row : result.rows) {
                if (!row.empty() && !trim(row[0]).empty())
                    resolved_values.insert(trim(row[0]));
            }
        } catch (...) {
            // A bridge may not reach the requested target. Other validated
            // bridges can still resolve it; failure never authorizes guessing.
        }
    }

    if (resolved_values.empty())
        return {IdentityResolutionStatus::NoMatch, {}, 0};
    if (resolved_values.size() > 1)
        return {IdentityResolutionStatus::Ambiguous, {},
                resolved_values.size()};
    return {IdentityResolutionStatus::Unique,
            *resolved_values.begin(), 1};
}

QueryResult Engine::universal_lookup(
        const std::vector<std::string>& output_fields,
        const std::string& entered_value,
        std::size_t max_anchor_rows) const {
    if (output_fields.empty())
        throw std::runtime_error(
            "Universal lookup requires at least one output field");
    const auto value = trim(entered_value);
    if (value.empty())
        throw std::runtime_error(
            "Universal lookup value cannot be blank");
    if (max_anchor_rows < 1 || max_anchor_rows > 10'000)
        throw std::runtime_error(
            "Universal lookup anchor limit is invalid");

    std::map<std::string, std::string> candidate_fields;
    std::map<std::string, std::size_t> candidate_anchor_rows;
    for (std::size_t dataset_id = 0;
         dataset_id < datasets_.size(); ++dataset_id) {
        const auto& dataset = datasets_[dataset_id];
        for (const auto& [field, column] :
             dataset.normalized_header_index) {
            const auto& index = exact_value_index(dataset_id, column);
            const auto found = index.find(indexed_value_key(
                dataset_id, column, value));
            if (found == index.end()) continue;
            candidate_anchor_rows[field] += found->second.size();
            candidate_fields.try_emplace(
                field, dataset.headers[column]);
        }
    }

    QueryResult combined;
    combined.headers = output_fields;
    static const std::unordered_set<std::string> strong_identity_fields = {
        "employeeid", "username", "samaccountname", "email", "userid",
        "userprincipalname"
    };
    static const std::unordered_set<std::string> person_name_fields = {
        "displayname", "fullname", "name", "firstname", "givenname",
        "lastname", "surname"
    };
    const bool has_strong_identity_match = std::any_of(
        candidate_fields.begin(), candidate_fields.end(),
        [&](const auto& candidate) {
            return strong_identity_fields.contains(candidate.first);
        });
    const bool has_person_name_match = std::any_of(
        candidate_fields.begin(), candidate_fields.end(),
        [&](const auto& candidate) {
            return person_name_fields.contains(candidate.first);
        });

    // A name is descriptive data, not a safe join key. Resolve it to one
    // trusted identity before traversing relationships, even when that name
    // exists exactly in one or more imported sheets. This prevents a shared
    // surname or repeated display-name row from mixing unrelated employees.
    if (!has_strong_identity_match &&
        (candidate_fields.empty() || has_person_name_match)) {
        // A production directory commonly stores Display Name as
        // "Last, First" while an operator naturally enters "First Last".
        // Resolve the token-equivalent name to one unique identity, then run
        // the normal relationship-aware lookup from that trusted anchor.
        // Never guess when two people share the same name.
        static const std::vector<std::string> identity_anchors = {
            "Employee ID", "Username", "SAM Account Name", "Email", "User ID",
            "User Principal Name"
        };
        for (const auto& identity_field : identity_anchors) {
            const auto resolution = resolve_identity_from_name(
                identity_field, value);
            if (resolution.status == IdentityResolutionStatus::Ambiguous) {
                combined.explanation =
                    "The entered name matches multiple people. Enter a "
                    "unique Employee ID, Username, or Email value.";
                return combined;
            }
            if (resolution.status != IdentityResolutionStatus::Unique ||
                trim(resolution.value).empty() ||
                normalize_name(resolution.value) == normalize_name(value)) {
                continue;
            }
            QueryRequest name_request;
            name_request.conditions.push_back(
                {identity_field, resolution.value});
            name_request.output_fields = output_fields;
            auto resolved = query(name_request);
            resolved.explanation =
                "The entered name was matched independent of First/Last "
                "order and resolved through " + identity_field + ". " +
                resolved.explanation;
            return resolved;
        }
        const bool output_only_names = std::all_of(
            output_fields.begin(), output_fields.end(),
            [&](const auto& field) {
                return person_name_fields.contains(
                    canonical_field_name(field));
            });
        if (has_person_name_match && !output_only_names) {
            combined.explanation =
                "The entered name could not be resolved to one trusted "
                "identity. Enter a unique Employee ID, Username, Email, or "
                "a complete First and Last Name.";
            return combined;
        }
        if (candidate_fields.empty()) {
            combined.explanation =
                "The value was not found in any imported field.";
            return combined;
        }
    }

    // If the exact value is already a strong identifier, never broaden it
    // through an incidental name-field collision.
    if (has_strong_identity_match) {
        for (auto iterator = candidate_fields.begin();
             iterator != candidate_fields.end();) {
            if (!strong_identity_fields.contains(iterator->first))
                iterator = candidate_fields.erase(iterator);
            else
                ++iterator;
        }
    }

    // Prefer the user's requested output type when the entered value exists
    // there. For example, an Employee ID may also occur in Manager Employee
    // ID for every direct report. If Employee ID is a requested output, the
    // exact Employee ID row is the intended anchor; Manager Employee ID must
    // not expand that single lookup into the manager's entire team. When no
    // requested output field contains the value, retain all candidates so
    // cross-type lookups such as Computer Name -> Username still work.
    std::set<std::string> requested_field_names;
    for (const auto& field : output_fields)
        requested_field_names.insert(canonical_field_name(field));
    const bool requested_field_matched = std::any_of(
        candidate_fields.begin(), candidate_fields.end(),
        [&](const auto& candidate) {
            return requested_field_names.contains(candidate.first);
        });
    if (requested_field_matched) {
        for (auto iterator = candidate_fields.begin();
             iterator != candidate_fields.end();) {
            if (!requested_field_names.contains(iterator->first))
                iterator = candidate_fields.erase(iterator);
            else
                ++iterator;
        }
    }
    std::size_t anchor_rows = 0;
    for (const auto& [field, display] : candidate_fields) {
        (void)display;
        anchor_rows += candidate_anchor_rows[field];
        if (anchor_rows > max_anchor_rows)
            throw std::runtime_error(
                "Universal lookup value is too broad: it matches more "
                "than " + std::to_string(max_anchor_rows) +
                " source rows in the selected field type. Enter a more "
                "specific value.");
    }

    // Preserve multiplicity inside one matched field type: separate source
    // rows (including rows on different worksheets) are real matches even
    // when their displayed values are identical. Only suppress the same
    // displayed result when it is rediscovered through a different field
    // type, such as Employee ID and Manager Employee ID.
    std::set<std::string> prior_field_rows;
    std::set<std::string> used_sources;
    for (const auto& [normalized, display] : candidate_fields) {
        (void)normalized;
        try {
            QueryRequest request;
            request.conditions.push_back({display, value});
            request.output_fields = output_fields;
            const auto result = query(request);
            std::set<std::string> current_field_rows;
            for (const auto& row : result.rows) {
                std::string key;
                for (const auto& cell : row) {
                    key += normalize_name(cell);
                    key.push_back('\x1e');
                }
                if (!prior_field_rows.contains(key))
                    combined.rows.push_back(row);
                current_field_rows.insert(std::move(key));
                if (combined.rows.size() > limits_.max_result_rows)
                    throw std::runtime_error(
                        "Universal lookup result safety limit exceeded");
            }
            used_sources.insert(
                result.sources.begin(), result.sources.end());
            prior_field_rows.insert(
                current_field_rows.begin(), current_field_rows.end());
        } catch (const std::exception&) {
            // A value can occur in unrelated fields. Only candidate paths
            // that can reach every requested output field contribute rows.
        }
    }
    combined.sources.assign(used_sources.begin(), used_sources.end());
    combined.explanation = combined.rows.empty()
        ? "The value was found, but no validated relationship reached the "
          "requested output field(s)."
        : std::string(requested_field_matched
              ? "Universal exact-value lookup anchored to a requested "
                "output field across "
              : "Universal exact-value lookup across ") +
          std::to_string(candidate_fields.size()) +
          " matching field type(s), with deduplicated related results.";
    return combined;
}

QueryResult Engine::query(const QueryRequest& request) const {
    std::vector<QueryCondition> conditions = request.conditions;
    if (conditions.empty() &&
        !trim(request.lookup_field).empty() &&
        !trim(request.lookup_value).empty()) {
        conditions.push_back(
            {request.lookup_field, request.lookup_value});
    }
    if (conditions.empty())
        throw std::runtime_error(
            "Enter at least one exact-match condition");
    if (request.output_fields.empty())
        throw std::runtime_error("At least one output field is required");

    for (const auto& condition : conditions) {
        if (trim(condition.field).empty() ||
            trim(condition.value).empty()) {
            throw std::runtime_error(
                "Condition fields and values cannot be blank");
        }
    }

    std::set<std::string> needed_fields;
    for (const auto& condition : conditions)
        needed_fields.insert(canonical_field_name(condition.field));
    for (const auto& field : request.output_fields)
        needed_fields.insert(canonical_field_name(field));

    // Use the condition found in the fewest reports as the anchor. This
    // reduces duplicate seeds when a shared key appears in many reports.
    std::size_t anchor_index = 0;
    std::size_t anchor_dataset_count =
        std::numeric_limits<std::size_t>::max();
    for (std::size_t i = 0; i < conditions.size(); ++i) {
        const auto normalized = canonical_field_name(conditions[i].field);
        std::size_t count = 0;
        for (const auto& dataset : datasets_) {
            if (dataset.normalized_header_index.contains(normalized))
                ++count;
        }
        if (count == 0)
            throw std::runtime_error(
                "Condition field was not found: " +
                conditions[i].field);
        if (count < anchor_dataset_count) {
            anchor_dataset_count = count;
            anchor_index = i;
        }
    }

    const auto lookup_name =
        canonical_field_name(conditions[anchor_index].field);
    const auto lookup_value =
        trim(conditions[anchor_index].value);
    static const std::unordered_set<std::string> strong_identity_lookups = {
        "employeeid", "username", "samaccountname", "email", "userid",
        "userprincipalname"
    };
    const bool strong_identity_lookup =
        strong_identity_lookups.contains(lookup_name);
    struct Seed { std::size_t ds; std::size_t row; };
    std::vector<Seed> seeds;
    std::vector<std::pair<std::size_t, std::size_t>> seed_columns;
    for (std::size_t d = 0; d < datasets_.size(); ++d) {
        auto it = datasets_[d].normalized_header_index.find(lookup_name);
        if (it != datasets_[d].normalized_header_index.end())
            seed_columns.push_back({d, it->second});
    }
    auto owns_all_outputs = [&](std::size_t dataset_id) {
        const auto& fields = datasets_[dataset_id].normalized_header_index;
        return std::all_of(
            request.output_fields.begin(), request.output_fields.end(),
            [&](const std::string& field) {
                return fields.contains(canonical_field_name(field));
            });
    };
    // When a matching row already owns every requested output, it is the
    // authoritative source. Related bridge sheets that only repeat the lookup
    // key must not create an extra copy of that same entity. If several
    // same-schema worksheets own all outputs, every one remains eligible.
    const bool has_complete_matching_source = std::any_of(
        seed_columns.begin(), seed_columns.end(),
        [&](const auto& candidate) {
            if (!owns_all_outputs(candidate.first)) return false;
            const auto& index = exact_value_index(
                candidate.first, candidate.second);
            return index.contains(indexed_value_key(
                candidate.first, candidate.second, lookup_value));
        });
    for (const auto& [d, column] : seed_columns) {
        // For descriptive/non-identity lookups, a complete source avoids
        // redundant bridge-sheet copies. For a strong person identity,
        // partial reports remain essential: they may contain a newer or
        // conflicting Email/SAM value that a complete report does not.
        if (!strong_identity_lookup &&
            has_complete_matching_source && !owns_all_outputs(d))
            continue;
        const auto& index = exact_value_index(d, column);
        const auto found = index.find(
            indexed_value_key(d, column, lookup_value));
        if (found == index.end()) continue;
        for (const auto row_id : found->second) {
            seeds.push_back({d, row_id});
            if (seeds.size() > limits_.max_result_rows)
                throw std::runtime_error("Result row safety limit exceeded");
        }
    }
    QueryResult result;
    result.headers = request.output_fields;
    if (seeds.empty()) {
        result.explanation = "No exact match was found.";
        return result;
    }

    std::set<std::string> used_sources;
    // Deduplicate only when two seeds resolve to the exact same set of source
    // dataset/row identities. Distinct worksheet rows remain distinct even if
    // their displayed values happen to be identical.
    std::set<std::string> seen_evidence_states;
    std::set<std::string> seen_identity_outputs;
    for (const auto& seed : seeds) {
        struct MatchState {
            std::unordered_map<std::size_t, std::size_t> rows;
            bool fanout_used = false;
        };
        std::vector<MatchState> states(1);
        states.front().rows[seed.ds] = seed.row;
        bool changed = true;
        while (changed) {
            changed = false;
            for (const auto& rel : relationships_) {
                std::vector<MatchState> expanded;
                for (const auto& state : states) {
                    std::size_t from, to, from_col, to_col;
                    if (state.rows.contains(rel.left_dataset) &&
                        !state.rows.contains(rel.right_dataset)) {
                        from = rel.left_dataset;
                        to = rel.right_dataset;
                        from_col = rel.left_column;
                        to_col = rel.right_column;
                    } else if (
                        state.rows.contains(rel.right_dataset) &&
                        !state.rows.contains(rel.left_dataset)) {
                        from = rel.right_dataset;
                        to = rel.left_dataset;
                        from_col = rel.right_column;
                        to_col = rel.left_column;
                    } else {
                        expanded.push_back(state);
                        continue;
                    }

                    bool target_adds_needed_field = false;
                    for (const auto& needed : needed_fields) {
                        bool already_available = false;
                        for (const auto& [matched_dataset, matched_row] :
                             state.rows) {
                            (void)matched_row;
                            if (datasets_[matched_dataset]
                                    .normalized_header_index.contains(
                                        needed)) {
                                already_available = true;
                                break;
                            }
                        }
                        if (!already_available &&
                            datasets_[to]
                                .normalized_header_index.contains(needed)) {
                            target_adds_needed_field = true;
                            break;
                        }
                    }
                    // Permit one validated intermediate dataset when it is
                    // the bridge to a requested field.  A common production
                    // path is SAM Account Name -> Logged On Users -> Computer
                    // Name -> Operating System.  The logged-user report does
                    // not own Operating System, but its Computer Name is the
                    // only safe key into the computer inventory that does.
                    // This remains bounded to an already discovered
                    // relationship and one schema hop; row-value matching and
                    // the fan-out/cross-product protections below still apply.
                    if (!target_adds_needed_field) {
                        for (const auto& bridge : relationships_) {
                            std::size_t next_dataset = datasets_.size();
                            if (bridge.left_dataset == to)
                                next_dataset = bridge.right_dataset;
                            else if (bridge.right_dataset == to)
                                next_dataset = bridge.left_dataset;
                            if (next_dataset >= datasets_.size() ||
                                state.rows.contains(next_dataset)) {
                                continue;
                            }
                            for (const auto& needed : needed_fields) {
                                bool already_available = false;
                                for (const auto& [matched_dataset,
                                                 matched_row] : state.rows) {
                                    (void)matched_row;
                                    if (datasets_[matched_dataset]
                                            .normalized_header_index
                                            .contains(needed)) {
                                        already_available = true;
                                        break;
                                    }
                                }
                                if (!already_available &&
                                    datasets_[next_dataset]
                                        .normalized_header_index
                                        .contains(needed)) {
                                    target_adds_needed_field = true;
                                    break;
                                }
                            }
                            if (target_adds_needed_field) break;
                        }
                    }
                    if (!target_adds_needed_field) {
                        expanded.push_back(state);
                        continue;
                    }

                    const auto& source_row =
                        datasets_[from].rows[state.rows.at(from)];
                    if (from_col >= source_row.size()) {
                        expanded.push_back(state);
                        continue;
                    }
                    const auto& target_index =
                        exact_value_index(to, to_col);
                    std::vector<std::size_t> related_rows;
                    std::unordered_set<std::size_t> unique_related_rows;
                    const auto source_field =
                        index_semantics_field(datasets_[from], from_col);
                    for (const auto& key : indexed_values_for(
                             source_field, source_row[from_col])) {
                        const auto found_rows = target_index.find(key);
                        if (found_rows == target_index.end()) continue;
                        for (const auto found_row : found_rows->second) {
                            if (unique_related_rows.insert(found_row).second)
                                related_rows.push_back(found_row);
                        }
                    }
                    if (related_rows.empty()) {
                        expanded.push_back(state);
                        continue;
                    }
                    if (related_rows.size() > 1 &&
                        state.fanout_used) {
                        throw std::runtime_error(
                            "Multiple one-to-many joins would create an "
                            "unsafe cross product");
                    }
                    for (const auto found_row : related_rows) {
                        auto branch = state;
                        branch.rows[to] = found_row;
                        if (related_rows.size() > 1)
                            branch.fanout_used = true;
                        expanded.push_back(std::move(branch));
                        if (expanded.size() >
                            limits_.max_result_rows) {
                            throw std::runtime_error(
                                "Result row safety limit exceeded");
                        }
                    }
                    changed = true;
                }
                states = std::move(expanded);
            }
        }

        for (const auto& state : states) {
            const auto& matched_rows = state.rows;
            bool conditions_match = true;
            for (const auto& condition : conditions) {
                const auto normalized = canonical_field_name(condition.field);
                bool field_found = false;
                bool value_found = false;
                for (const auto& [dataset_id, row_id] : matched_rows) {
                    const auto hit =
                        datasets_[dataset_id].normalized_header_index.find(
                            normalized);
                    if (hit ==
                        datasets_[dataset_id].normalized_header_index.end())
                        continue;
                    field_found = true;
                    const auto& row = datasets_[dataset_id].rows[row_id];
                    const auto wanted = normalized_field_value(
                        normalized, condition.value);
                    const auto stored_values = hit->second < row.size()
                        ? indexed_values_for(
                            index_semantics_field(
                                datasets_[dataset_id], hit->second),
                            row[hit->second])
                        : std::vector<std::string>{};
                    if (!wanted.empty() &&
                        std::find(stored_values.begin(), stored_values.end(),
                                  wanted) != stored_values.end()) {
                        value_found = true;
                        break;
                    }
                }
                if (!field_found || !value_found) {
                    conditions_match = false;
                    break;
                }
            }
            if (!conditions_match) continue;

            std::vector<std::string> output;
            output.reserve(request.output_fields.size());
            for (const auto& requested : request.output_fields) {
                const auto normalized = canonical_field_name(requested);
                std::string value;
                // The row that contained the operator's exact lookup is the
                // identity authority for every field it owns.  Previously,
                // unordered joined rows could supply Employee ID before the
                // seed row, making a Username lookup appear to return random
                // people from a related membership/group report.
                const auto& seed_dataset = datasets_[seed.ds];
                const auto seed_hit =
                    seed_dataset.normalized_header_index.find(normalized);
                if (seed_hit !=
                        seed_dataset.normalized_header_index.end() &&
                    seed_hit->second <
                        seed_dataset.rows[seed.row].size()) {
                    value = seed_dataset.rows[seed.row][seed_hit->second];
                    used_sources.insert(seed_dataset.name);
                }
                for (const auto& [dataset_id, row_id] : matched_rows) {
                    if (!value.empty()) break;
                    const auto hit =
                        datasets_[dataset_id]
                            .normalized_header_index.find(normalized);
                    if (hit != datasets_[dataset_id]
                                   .normalized_header_index.end()) {
                        value =
                            datasets_[dataset_id].rows[row_id][hit->second];
                        used_sources.insert(datasets_[dataset_id].name);
                        break;
                    }
                }
                output.push_back(std::move(value));
            }
            // A person-to-device join can legitimately reach a row that owns
            // Computer Name while a different inventory workbook owns
            // Operating System, Version, Status, or BitLocker details.  If a
            // requested device field is still blank, enrich it by an exact
            // Computer Name lookup across datasets that contain both fields.
            // Fill only when every matching non-empty value agrees; conflicting
            // inventory values remain blank rather than being guessed.
            const auto computer_output = std::find_if(
                request.output_fields.begin(), request.output_fields.end(),
                [&](const auto& field) {
                    return canonical_field_name(field) == "computername";
                });
            if (computer_output != request.output_fields.end()) {
                const auto computer_column = static_cast<std::size_t>(
                    std::distance(
                        request.output_fields.begin(), computer_output));
                if (computer_column < output.size() &&
                    !trim(output[computer_column]).empty()) {
                    const auto computer_value = output[computer_column];
                    for (std::size_t output_column = 0;
                         output_column < output.size(); ++output_column) {
                        if (!trim(output[output_column]).empty() ||
                            output_column == computer_column) {
                            continue;
                        }
                        const auto requested_name = canonical_field_name(
                            request.output_fields[output_column]);
                        std::map<std::string,
                                 std::pair<std::string, std::string>>
                            agreed_values;
                        for (std::size_t dataset_id = 0;
                             dataset_id < datasets_.size(); ++dataset_id) {
                            const auto& dataset = datasets_[dataset_id];
                            const auto computer_hit =
                                dataset.normalized_header_index.find(
                                    "computername");
                            const auto requested_hit =
                                dataset.normalized_header_index.find(
                                    requested_name);
                            if (computer_hit ==
                                    dataset.normalized_header_index.end() ||
                                requested_hit ==
                                    dataset.normalized_header_index.end()) {
                                continue;
                            }
                            const auto& computer_index = exact_value_index(
                                dataset_id, computer_hit->second);
                            const auto matching_rows = computer_index.find(
                                indexed_value_key(
                                    dataset_id, computer_hit->second,
                                    computer_value));
                            if (matching_rows == computer_index.end())
                                continue;
                            for (const auto row_id : matching_rows->second) {
                                if (row_id >= dataset.rows.size() ||
                                    requested_hit->second >=
                                        dataset.rows[row_id].size()) {
                                    continue;
                                }
                                const auto candidate = trim(
                                    dataset.rows[row_id][requested_hit->second]);
                                if (candidate.empty()) continue;
                                agreed_values.try_emplace(
                                    normalize_name(candidate), candidate,
                                    dataset.name);
                            }
                        }
                        if (agreed_values.size() == 1) {
                            output[output_column] =
                                agreed_values.begin()->second.first;
                            used_sources.insert(
                                agreed_values.begin()->second.second);
                        }
                    }
                }
            }
            std::string output_signature;
            for (const auto& value : output) {
                output_signature += std::to_string(value.size());
                output_signature.push_back(':');
                output_signature += value;
                output_signature.push_back(';');
            }
            std::vector<std::pair<std::size_t, std::size_t>> evidence_rows(
                matched_rows.begin(), matched_rows.end());
            std::sort(evidence_rows.begin(), evidence_rows.end());
            std::string evidence_signature;
            for (const auto& [dataset_id, row_id] : evidence_rows) {
                evidence_signature += std::to_string(dataset_id);
                evidence_signature.push_back(':');
                evidence_signature += std::to_string(row_id);
                evidence_signature.push_back(';');
            }
            evidence_signature.push_back('|');
            evidence_signature += output_signature;
            if (!seen_evidence_states.insert(evidence_signature).second)
                continue;
            // The same Employee ID/Username is often copied into many
            // reports. Collapse byte-for-byte equivalent displayed profiles
            // for strong identities, but keep distinct values (for example
            // two different Emails or Computers) so conflicts and genuine
            // one-to-many relationships remain visible.
            if (strong_identity_lookup &&
                !seen_identity_outputs.insert(output_signature).second) {
                continue;
            }
            result.rows.push_back(std::move(output));
            if (result.rows.size() > limits_.max_result_rows)
                throw std::runtime_error(
                    "Result row safety limit exceeded");
        }
    }
    // Deterministic AD group enrichment. Once an identity row contains a
    // Display Name but Group Name is still blank, query the already indexed
    // original Members columns directly. This exact token lookup is the same
    // operation that succeeds when an operator searches Members manually, and
    // does not depend on relationship overlap/uniqueness inference.
    const auto display_output = std::find_if(
        request.output_fields.begin(), request.output_fields.end(),
        [&](const auto& field) {
            const auto name = canonical_field_name(field);
            return name == "displayname" || name == "fullname" ||
                   name == "name";
        });
    const auto group_output = std::find_if(
        request.output_fields.begin(), request.output_fields.end(),
        [&](const auto& field) {
            return canonical_field_name(field) == "groupname";
        });
    const auto identity_output = std::find_if(
        request.output_fields.begin(), request.output_fields.end(),
        [&](const auto& field) {
            const auto name = canonical_field_name(field);
            return name == "samaccountname" || name == "username" ||
                   name == "employeeid" || name == "userid" ||
                   name == "userprincipalname" || name == "email";
        });
    if (group_output != request.output_fields.end() &&
        (display_output != request.output_fields.end() ||
         identity_output != request.output_fields.end())) {
        const auto display_column = display_output == request.output_fields.end()
            ? request.output_fields.size()
            : static_cast<std::size_t>(std::distance(
                request.output_fields.begin(), display_output));
        const auto identity_column = identity_output == request.output_fields.end()
            ? request.output_fields.size()
            : static_cast<std::size_t>(std::distance(
                request.output_fields.begin(), identity_output));
        const auto group_column = static_cast<std::size_t>(std::distance(
            request.output_fields.begin(), group_output));
        std::vector<std::vector<std::string>> expanded_rows;
        for (const auto& existing : result.rows) {
            if (group_column >= existing.size()) {
                expanded_rows.push_back(existing);
                continue;
            }
            std::set<std::string> display_values;
            if (display_column < existing.size() &&
                !trim(existing[display_column]).empty()) {
                display_values.insert(trim(existing[display_column]));
            }
            // Display Name is an internal relationship bridge, not a
            // mandatory visible output. Resolve it from a strong requested
            // identity so `SAM Account Name | Group Name` behaves exactly
            // like `SAM Account Name | Display Name | Group Name`.
            if (display_values.empty() && identity_column < existing.size() &&
                !trim(existing[identity_column]).empty()) {
                const auto identity_field = canonical_field_name(
                    request.output_fields[identity_column]);
                for (std::size_t dataset_id = 0;
                     dataset_id < datasets_.size(); ++dataset_id) {
                    const auto& dataset = datasets_[dataset_id];
                    const auto identity_hit =
                        dataset.normalized_header_index.find(identity_field);
                    if (identity_hit == dataset.normalized_header_index.end())
                        continue;
                    std::optional<std::size_t> name_column;
                    for (const auto& candidate : {
                             std::string("displayname"),
                             std::string("fullname"), std::string("name")}) {
                        const auto hit =
                            dataset.normalized_header_index.find(candidate);
                        if (hit != dataset.normalized_header_index.end()) {
                            name_column = hit->second;
                            break;
                        }
                    }
                    if (!name_column) continue;
                    const auto& index = exact_value_index(
                        dataset_id, identity_hit->second);
                    const auto rows = index.find(indexed_value_key(
                        dataset_id, identity_hit->second,
                        existing[identity_column]));
                    if (rows == index.end()) continue;
                    for (const auto row_id : rows->second) {
                        if (row_id >= dataset.rows.size() ||
                            *name_column >= dataset.rows[row_id].size()) continue;
                        const auto name = trim(dataset.rows[row_id][*name_column]);
                        if (!name.empty()) display_values.insert(name);
                    }
                }
            }
            if (display_values.empty()) {
                expanded_rows.push_back(existing);
                continue;
            }
            std::set<std::string> distinct_people;
            for (const auto& display_value : display_values) {
                auto key = person_name_key(display_value);
                if (key.empty()) key = normalize_name(display_value);
                if (!key.empty()) distinct_people.insert(std::move(key));
            }
            if (distinct_people.size() > 1) {
                throw std::runtime_error(
                    "The requested identity maps to multiple Display Names. "
                    "Point blocked group enrichment to prevent unrelated "
                    "memberships from being combined.");
            }
            std::set<std::pair<std::size_t, std::size_t>> member_matches;
            std::set<std::string> member_keys;
            for (const auto& display_value : display_values) {
                for (const auto& key : indexed_field_values(
                         "displayname", display_value)) member_keys.insert(key);
            }
            for (std::size_t dataset_id = 0;
                 dataset_id < datasets_.size(); ++dataset_id) {
                const auto& dataset = datasets_[dataset_id];
                if (!dataset.normalized_header_index.contains("groupname"))
                    continue;
                for (std::size_t column = 0;
                     column < dataset.headers.size(); ++column) {
                    const auto original = normalize_name(
                        dataset.headers[column]);
                    if (original != "members" && original != "member" &&
                        original != "membernames" &&
                        original != "membersnames") {
                        continue;
                    }
                    const auto& member_index = exact_value_index(
                        dataset_id, column);
                    for (const auto& key : member_keys) {
                        const auto found = member_index.find(key);
                        if (found == member_index.end()) continue;
                        for (const auto row_id : found->second)
                            member_matches.insert({dataset_id, row_id});
                    }
                }
            }
            if (member_matches.empty()) {
                expanded_rows.push_back(existing);
                continue;
            }
            for (const auto& [dataset_id, row_id] : member_matches) {
                const auto& dataset = datasets_[dataset_id];
                if (row_id >= dataset.rows.size()) continue;
                auto enriched = existing;
                // The inferred relationship may have supplied only one of
                // several groups. Rebuild Group Name from the complete exact
                // Members index so every membership participates in Compare.
                enriched[group_column].clear();
                for (std::size_t column = 0;
                     column < request.output_fields.size(); ++column) {
                    if (column >= enriched.size() ||
                        !trim(enriched[column]).empty()) {
                        continue;
                    }
                    const auto requested = canonical_field_name(
                        request.output_fields[column]);
                    const auto source_column =
                        dataset.normalized_header_index.find(requested);
                    if (source_column ==
                            dataset.normalized_header_index.end() ||
                        source_column->second >= dataset.rows[row_id].size()) {
                        continue;
                    }
                    enriched[column] =
                        dataset.rows[row_id][source_column->second];
                }
                expanded_rows.push_back(std::move(enriched));
                used_sources.insert(dataset.name);
                if (expanded_rows.size() > limits_.max_result_rows)
                    throw std::runtime_error(
                        "Group membership result safety limit exceeded");
            }
        }
        std::set<std::string> seen_expanded;
        result.rows.clear();
        for (auto& row : expanded_rows) {
            std::string signature;
            for (const auto& value : row) {
                signature += normalize_name(value);
                signature.push_back('\x1e');
            }
            if (seen_expanded.insert(signature).second)
                result.rows.push_back(std::move(row));
        }
    }
    result.sources.assign(used_sources.begin(), used_sources.end());
    result.explanation =
        "Exact multi-field AND filtering with identity-safe relationship "
        "joins and displayed-row deduplication.";
    return result;
}

QueryResult Engine::count_related(
        const std::vector<std::string>& fields,
        const std::vector<std::string>& exact_values,
        const std::string& source_name) const {
    if (!exact_values.empty() &&
        exact_values.size() != fields.size()) {
        throw std::runtime_error(
            "Cross-report Count values do not match the selected fields");
    }

    std::vector<std::string> normalized_fields;
    for (const auto& field : fields)
        normalized_fields.push_back(canonical_field_name(field));
    const bool has_exact_filters =
        !exact_values.empty() &&
        std::any_of(
            exact_values.begin(), exact_values.end(),
            [](const auto& value) {
                return !trim(value).empty();
            });
    const bool has_group_fields =
        exact_values.empty() ||
        std::any_of(
            exact_values.begin(), exact_values.end(),
            [](const auto& value) {
                return trim(value).empty();
            });

    const std::vector<std::string> identity_candidates = {
        "employeeid", "username", "userid", "userprincipalname",
        "computerid", "computername", "deviceid", "assetid", "assettag"
    };
    std::string identity;
    std::vector<std::vector<std::size_t>> field_candidates;
    for (const auto& candidate : identity_candidates) {
        std::vector<std::vector<std::size_t>> possible(fields.size());
        bool covers_every_field = true;
        for (std::size_t field_id = 0;
             field_id < normalized_fields.size(); ++field_id) {
            for (std::size_t dataset_id = 0;
                 dataset_id < datasets_.size(); ++dataset_id) {
                const auto& indexes =
                    datasets_[dataset_id].normalized_header_index;
                if (indexes.contains(candidate) &&
                    indexes.contains(normalized_fields[field_id])) {
                    possible[field_id].push_back(dataset_id);
                }
            }
            if (possible[field_id].empty()) {
                covers_every_field = false;
                break;
            }
        }
        if (covers_every_field) {
            identity = candidate;
            field_candidates = std::move(possible);
            break;
        }
    }
    if (identity.empty())
        throw std::runtime_error(
            "The selected Count fields cannot be connected through a "
            "shared Employee ID, Username, Computer ID, or other safe "
            "identity field");

    auto mappings_agree = [&](std::size_t left_id,
                              std::size_t right_id,
                              const std::string& field) {
        const auto& left = datasets_[left_id];
        const auto& right = datasets_[right_id];
        const auto left_key =
            left.normalized_header_index.at(identity);
        const auto right_key =
            right.normalized_header_index.at(identity);
        const auto left_value =
            left.normalized_header_index.at(field);
        const auto right_value =
            right.normalized_header_index.at(field);
        std::map<std::string, std::set<std::string>> left_map;
        std::map<std::string, std::set<std::string>> right_map;
        for (const auto& row : left.rows) {
            if (left_key >= row.size() || left_value >= row.size())
                continue;
            const auto key = normalize_name(trim(row[left_key]));
            const auto value = normalize_name(trim(row[left_value]));
            if (!key.empty() && !value.empty())
                left_map[key].insert(value);
        }
        for (const auto& row : right.rows) {
            if (right_key >= row.size() || right_value >= row.size())
                continue;
            const auto key = normalize_name(trim(row[right_key]));
            const auto value = normalize_name(trim(row[right_value]));
            if (!key.empty() && !value.empty())
                right_map[key].insert(value);
        }
        for (const auto& [key, values] : left_map) {
            const auto found = right_map.find(key);
            if (found != right_map.end() &&
                found->second != values) {
                return false;
            }
        }
        return true;
    };

    std::vector<std::size_t> selected_datasets;
    selected_datasets.reserve(fields.size());
    for (std::size_t field_id = 0;
         field_id < fields.size(); ++field_id) {
        const auto& candidates = field_candidates[field_id];
        std::optional<std::size_t> selected;
        if (!trim(source_name).empty()) {
            for (const auto dataset_id : candidates) {
                if (iequals_ascii(
                        datasets_[dataset_id].name, source_name)) {
                    selected = dataset_id;
                    break;
                }
            }
        }
        if (!selected && candidates.size() == 1) {
            selected = candidates.front();
        }
        if (!selected) {
            selected = authoritative_count_dataset(
                datasets_, candidates,
                {normalized_fields[field_id]});
        }
        if (!selected) {
            bool equivalent = true;
            for (std::size_t i = 1; i < candidates.size(); ++i) {
                if (!mappings_agree(
                        candidates.front(), candidates[i],
                        normalized_fields[field_id])) {
                    equivalent = false;
                    break;
                }
            }
            if (equivalent) selected = candidates.front();
        }
        if (!selected) {
            std::string message =
                "Cross-report Count field '" + fields[field_id] +
                "' has different meanings or values in multiple reports: ";
            for (std::size_t i = 0; i < candidates.size(); ++i) {
                if (i) message += ", ";
                message += datasets_[candidates[i]].name;
            }
            message +=
                ". Choose one with Workspace > Next Source or rename the "
                "report headings to be specific.";
            throw std::runtime_error(message);
        }
        selected_datasets.push_back(*selected);
    }

    std::string normalized_count_fields;
    for (const auto& field : normalized_fields) {
        normalized_count_fields += field;
        normalized_count_fields.push_back(';');
    }
    auto count_contains_any =
        [&](const std::vector<std::string>& terms) {
            return std::any_of(
                terms.begin(), terms.end(),
                [&](const auto& term) {
                    return normalized_count_fields.find(term) !=
                        std::string::npos;
                });
        };
    const bool device_count = count_contains_any({
        "device", "computer", "encryption", "patch", "crowdstrike",
        "vulnerability", "antivirus", "endpoint", "operatingsystem",
        "asset", "serialnumber"
    });
    const bool ticket_count = count_contains_any({
        "ticket", "incident", "priority", "resolution"
    });
    std::vector<std::string> related_candidates;
    if (device_count) {
        related_candidates = {
            "deviceid", "computerid", "computername", "assetid",
            "assettag", "serialnumber"
        };
    } else if (ticket_count) {
        related_candidates = {
            "ticketid", "incidentid", "caseid"
        };
    }
    related_candidates.push_back(identity);

    const DataSet* related_dataset = nullptr;
    std::size_t related_identity_column = 0;
    std::size_t related_value_column = 0;
    std::size_t best_related_rank = related_candidates.size();
    std::set<std::size_t> distinct_selected_datasets(
        selected_datasets.begin(), selected_datasets.end());
    for (const auto dataset_id : distinct_selected_datasets) {
        const auto& dataset = datasets_[dataset_id];
        const auto identity_hit =
            dataset.normalized_header_index.find(identity);
        if (identity_hit == dataset.normalized_header_index.end())
            continue;
        for (std::size_t rank = 0;
             rank < related_candidates.size(); ++rank) {
            const auto value_hit =
                dataset.normalized_header_index.find(
                    related_candidates[rank]);
            if (value_hit == dataset.normalized_header_index.end())
                continue;
            if (rank < best_related_rank) {
                related_dataset = &dataset;
                related_identity_column = identity_hit->second;
                related_value_column = value_hit->second;
                best_related_rank = rank;
            }
            break;
        }
    }

    std::map<std::string, std::set<std::string>>
        related_values_by_entity;
    std::string related_identity_field;
    if (related_dataset) {
        related_identity_field =
            related_dataset->headers[related_value_column];
        for (const auto& row : related_dataset->rows) {
            if (related_identity_column >= row.size() ||
                related_value_column >= row.size()) {
                continue;
            }
            const auto entity =
                normalize_name(trim(row[related_identity_column]));
            const auto related = trim(row[related_value_column]);
            if (!entity.empty() && !related.empty())
                related_values_by_entity[entity].insert(related);
        }
    }

    using ValuesByIdentity =
        std::map<std::string, std::map<std::string, std::string>>;
    std::vector<ValuesByIdentity> values_by_field(fields.size());
    std::set<std::string> used_sources;
    for (std::size_t field_id = 0;
         field_id < fields.size(); ++field_id) {
        const auto dataset_id = selected_datasets[field_id];
        const auto& dataset = datasets_[dataset_id];
        const auto identity_column =
            dataset.normalized_header_index.at(identity);
        const auto value_column =
            dataset.normalized_header_index.at(
                normalized_fields[field_id]);
        used_sources.insert(dataset.name);
        for (const auto& row : dataset.rows) {
            if (identity_column >= row.size() ||
                value_column >= row.size()) {
                continue;
            }
            const auto raw_identity = trim(row[identity_column]);
            const auto raw_value = trim(row[value_column]);
            if (raw_identity.empty() || raw_value.empty()) continue;
            values_by_field[field_id][
                normalize_name(raw_identity)].try_emplace(
                    normalize_name(raw_value), raw_value);
        }
    }

    std::set<std::string> entity_keys;
    if (!values_by_field.empty()) {
        for (const auto& [key, values] : values_by_field.front()) {
            (void)values;
            entity_keys.insert(key);
        }
    }
    std::map<std::vector<std::string>, std::size_t> counts;
    std::map<std::vector<std::string>, std::set<std::string>>
        related_values_by_group;
    for (const auto& entity : entity_keys) {
        std::vector<const std::map<std::string, std::string>*> values;
        std::size_t fanout_fields = 0;
        bool complete = true;
        for (std::size_t field_id = 0;
             field_id < fields.size(); ++field_id) {
            const auto found = values_by_field[field_id].find(entity);
            if (found == values_by_field[field_id].end() ||
                found->second.empty()) {
                complete = false;
                break;
            }
            values.push_back(&found->second);
            if (found->second.size() > 1) ++fanout_fields;
        }
        if (!complete) continue;
        if (fanout_fields > 1)
            throw std::runtime_error(
                "Cross-report Count found multiple independent one-to-many "
                "fields for one identity; counting their combinations would "
                "create an unsafe cross product");

        std::size_t fanout_index = fields.size();
        for (std::size_t i = 0; i < values.size(); ++i) {
            if (values[i]->size() > 1) {
                fanout_index = i;
                break;
            }
        }
        const std::size_t combinations =
            fanout_index == fields.size()
            ? 1 : values[fanout_index]->size();
        auto fanout_it =
            fanout_index == fields.size()
            ? values.front()->end()
            : values[fanout_index]->begin();
        for (std::size_t combination = 0;
             combination < combinations; ++combination) {
            std::vector<std::string> group;
            bool exact_match = true;
            for (std::size_t field_id = 0;
                 field_id < fields.size(); ++field_id) {
                const auto& selected_value =
                    field_id == fanout_index
                    ? fanout_it->second
                    : values[field_id]->begin()->second;
                group.push_back(selected_value);
                if (!exact_values.empty() &&
                    !trim(exact_values[field_id]).empty() &&
                    normalized_field_value(
                        normalized_fields[field_id], selected_value) !=
                    normalized_field_value(
                        normalized_fields[field_id],
                        exact_values[field_id])) {
                    exact_match = false;
                }
            }
            if (exact_match) {
                ++counts[group];
                const auto related =
                    related_values_by_entity.find(entity);
                if (related != related_values_by_entity.end()) {
                    related_values_by_group[group].insert(
                        related->second.begin(), related->second.end());
                }
            }
            if (fanout_index != fields.size()) ++fanout_it;
        }
    }

    QueryResult result;
    result.headers = fields;
    result.headers.push_back("Count");
    if (has_exact_filters && !has_group_fields) {
        std::size_t total = 0;
        for (const auto& [group, count] : counts) {
            (void)group;
            total += count;
        }
        auto row = exact_values;
        row.push_back(std::to_string(total));
        result.rows.push_back(std::move(row));
        std::set<std::string> all_related;
        for (const auto& [group, values] :
             related_values_by_group) {
            (void)group;
            all_related.insert(values.begin(), values.end());
        }
        result.related_identity_values.emplace_back(
            all_related.begin(), all_related.end());
    } else {
        for (const auto& [group, count] : counts) {
            auto row = group;
            row.push_back(std::to_string(count));
            result.rows.push_back(std::move(row));
            const auto related =
                related_values_by_group.find(group);
            if (related == related_values_by_group.end()) {
                result.related_identity_values.emplace_back();
            } else {
                result.related_identity_values.emplace_back(
                    related->second.begin(), related->second.end());
            }
        }
    }
    result.related_identity_field = related_identity_field;
    result.sources.assign(used_sources.begin(), used_sources.end());
    result.explanation =
        "Identity-safe counts combined across related reports using " +
        identity + ".";
    return result;
}

QueryResult Engine::count_groups(
        const std::vector<std::string>& group_fields,
        const std::string& source_name) const {
    if (group_fields.empty())
        throw std::runtime_error(
            "Type at least one field to count");

    std::vector<std::string> normalized_fields;
    normalized_fields.reserve(group_fields.size());
    for (const auto& field : group_fields) {
        if (trim(field).empty())
            throw std::runtime_error(
                "Count fields cannot be blank");
        normalized_fields.push_back(canonical_field_name(field));
    }

    std::map<std::vector<std::string>, std::size_t> counts;
    std::set<std::string> used_sources;
    std::vector<std::size_t> compatible_datasets;

    for (std::size_t dataset_id = 0;
         dataset_id < datasets_.size(); ++dataset_id) {
        const auto& dataset = datasets_[dataset_id];
        if (!trim(source_name).empty() &&
            !iequals_ascii(dataset.name, source_name)) {
            continue;
        }
        bool contains_all_fields = true;
        for (const auto& normalized : normalized_fields) {
            if (!dataset.normalized_header_index.contains(normalized)) {
                contains_all_fields = false;
                break;
            }
        }
        if (contains_all_fields)
            compatible_datasets.push_back(dataset_id);
    }

    if (compatible_datasets.empty())
        return count_related(group_fields, {}, source_name);
    if (compatible_datasets.size() > 1) {
        const auto authoritative =
            authoritative_count_dataset(
                datasets_, compatible_datasets,
                normalized_fields);
        if (authoritative) {
            compatible_datasets = {*authoritative};
        }
    }
    if (compatible_datasets.size() > 1) {
        std::string message =
            "Count fields are ambiguous because they occur together in "
            "multiple reports: ";
        for (std::size_t i = 0;
             i < compatible_datasets.size(); ++i) {
            if (i) message += ", ";
            message += datasets_[compatible_datasets[i]].name;
        }
        message +=
            ". Choose the intended report with Workspace > Next Source.";
        throw std::runtime_error(message);
    }

    for (const auto dataset_id : compatible_datasets) {
        const auto& dataset = datasets_[dataset_id];
        std::vector<std::size_t> columns;
        columns.reserve(normalized_fields.size());
        for (const auto& normalized : normalized_fields) {
            const auto found =
                dataset.normalized_header_index.find(normalized);
            columns.push_back(found->second);
        }

        used_sources.insert(dataset.name);
        for (const auto& row : dataset.rows) {
            std::vector<std::string> group;
            group.reserve(columns.size());
            bool any_value = false;
            for (const auto column : columns) {
                std::string value =
                    column < row.size() ? trim(row[column]) : std::string{};
                if (!value.empty()) any_value = true;
                group.push_back(std::move(value));
            }
            if (!any_value) continue;
            ++counts[group];
            if (counts.size() > limits_.max_result_rows)
                throw std::runtime_error(
                    "Count group safety limit exceeded");
        }
    }

    QueryResult result;
    result.headers = group_fields;
    result.headers.push_back("Count");
    result.rows.reserve(counts.size());
    for (const auto& [group, count] : counts) {
        auto output = group;
        output.push_back(std::to_string(count));
        result.rows.push_back(std::move(output));
    }
    result.sources.assign(used_sources.begin(), used_sources.end());
    result.explanation =
        "Grouped occurrence counts from the selected compatible report.";
    return result;
}

QueryResult Engine::count_mixed(
        const std::vector<std::string>& fields,
        const std::vector<std::string>& criteria,
        const std::string& source_name) const {
    if (fields.empty() || fields.size() != criteria.size())
        throw std::runtime_error(
            "Mixed Count fields and criteria do not match");

    std::vector<std::string> normalized_fields;
    normalized_fields.reserve(fields.size());
    bool has_filter = false;
    bool has_group = false;
    for (std::size_t index = 0; index < fields.size(); ++index) {
        if (trim(fields[index]).empty())
            throw std::runtime_error(
                "Mixed Count fields cannot be blank");
        normalized_fields.push_back(canonical_field_name(fields[index]));
        if (trim(criteria[index]).empty())
            has_group = true;
        else
            has_filter = true;
    }
    if (!has_filter || !has_group)
        throw std::runtime_error(
            "Mixed Count requires at least one filled filter and one "
            "blank grouping field");

    std::vector<std::size_t> compatible_datasets;
    for (std::size_t dataset_id = 0;
         dataset_id < datasets_.size(); ++dataset_id) {
        const auto& dataset = datasets_[dataset_id];
        if (!trim(source_name).empty() &&
            !iequals_ascii(dataset.name, source_name)) {
            continue;
        }
        bool contains_all_fields = true;
        for (const auto& normalized : normalized_fields) {
            if (!dataset.normalized_header_index.contains(normalized)) {
                contains_all_fields = false;
                break;
            }
        }
        if (contains_all_fields)
            compatible_datasets.push_back(dataset_id);
    }

    if (compatible_datasets.empty())
        return count_related(fields, criteria, source_name);
    if (compatible_datasets.size() > 1) {
        const auto authoritative =
            authoritative_count_dataset(
                datasets_, compatible_datasets,
                normalized_fields);
        if (authoritative) {
            compatible_datasets = {*authoritative};
        }
    }
    if (compatible_datasets.size() > 1) {
        std::string message =
            "Mixed Count fields are ambiguous because they occur "
            "together in multiple reports: ";
        for (std::size_t index = 0;
             index < compatible_datasets.size(); ++index) {
            if (index) message += ", ";
            message += datasets_[compatible_datasets[index]].name;
        }
        message +=
            ". Choose the intended report with Workspace > Next Source.";
        throw std::runtime_error(message);
    }

    const auto& dataset =
        datasets_[compatible_datasets.front()];
    std::vector<std::size_t> columns;
    columns.reserve(normalized_fields.size());
    for (const auto& normalized : normalized_fields)
        columns.push_back(
            dataset.normalized_header_index.at(normalized));

    std::map<std::vector<std::string>, std::size_t> counts;
    for (const auto& row : dataset.rows) {
        bool filters_match = true;
        std::vector<std::string> group;
        group.reserve(columns.size());
        for (std::size_t index = 0;
             index < columns.size(); ++index) {
            const auto value =
                columns[index] < row.size()
                ? trim(row[columns[index]]) : std::string{};
            group.push_back(value);
            if (!trim(criteria[index]).empty() &&
                normalized_field_value(
                    normalized_fields[index], value) !=
                normalized_field_value(
                    normalized_fields[index], criteria[index])) {
                filters_match = false;
                break;
            }
        }
        if (!filters_match) continue;
        ++counts[group];
        if (counts.size() > limits_.max_result_rows)
            throw std::runtime_error(
                "Mixed Count group safety limit exceeded");
    }

    QueryResult result;
    result.headers = fields;
    result.headers.push_back("Count");
    result.rows.reserve(counts.size());
    for (const auto& [group, count] : counts) {
        auto output = group;
        output.push_back(std::to_string(count));
        result.rows.push_back(std::move(output));
    }
    result.sources.push_back(dataset.name);
    result.explanation =
        "Exact filled criteria filtered the source; blank criteria fields "
        "were grouped and counted.";
    return result;
}

QueryResult Engine::count_exact(
        const std::vector<QueryCondition>& conditions,
        const std::string& source_name) const {
    if (conditions.empty())
        throw std::runtime_error(
            "Enter at least one exact value to count");

    std::vector<std::string> normalized_fields;
    normalized_fields.reserve(conditions.size());
    for (const auto& condition : conditions) {
        if (trim(condition.field).empty() ||
            trim(condition.value).empty()) {
            throw std::runtime_error(
                "Count fields and selected values cannot be blank");
        }
        normalized_fields.push_back(
            canonical_field_name(condition.field));
    }

    std::vector<std::size_t> compatible_datasets;
    for (std::size_t dataset_id = 0;
         dataset_id < datasets_.size(); ++dataset_id) {
        if (!trim(source_name).empty() &&
            !iequals_ascii(
                datasets_[dataset_id].name, source_name)) {
            continue;
        }
        bool contains_all_fields = true;
        for (const auto& normalized : normalized_fields) {
            if (!datasets_[dataset_id]
                     .normalized_header_index.contains(normalized)) {
                contains_all_fields = false;
                break;
            }
        }
        if (contains_all_fields)
            compatible_datasets.push_back(dataset_id);
    }

    if (compatible_datasets.empty()) {
        std::vector<std::string> fields;
        std::vector<std::string> values;
        for (const auto& condition : conditions) {
            fields.push_back(condition.field);
            values.push_back(condition.value);
        }
        return count_related(fields, values, source_name);
    }
    if (compatible_datasets.size() > 1) {
        const auto authoritative =
            authoritative_count_dataset(
                datasets_, compatible_datasets,
                normalized_fields);
        if (authoritative) {
            compatible_datasets = {*authoritative};
        }
    }
    if (compatible_datasets.size() > 1) {
        std::string message =
            "The selected count fields are ambiguous because they occur "
            "together in multiple reports: ";
        for (std::size_t i = 0;
             i < compatible_datasets.size(); ++i) {
            if (i) message += ", ";
            message += datasets_[compatible_datasets[i]].name;
        }
        message +=
            ". Add another exact field and value that identifies one report.";
        throw std::runtime_error(message);
    }

    const auto& dataset =
        datasets_[compatible_datasets.front()];
    std::vector<std::size_t> columns;
    columns.reserve(normalized_fields.size());
    for (const auto& normalized : normalized_fields) {
        columns.push_back(
            dataset.normalized_header_index.at(normalized));
    }

    std::size_t count = 0;
    for (const auto& row : dataset.rows) {
        bool matches = true;
        for (std::size_t i = 0;
             i < conditions.size(); ++i) {
            if (columns[i] >= row.size() ||
                !iequals_ascii(
                    trim(row[columns[i]]),
                    trim(conditions[i].value))) {
                matches = false;
                break;
            }
        }
        if (matches) ++count;
    }

    QueryResult result;
    for (const auto& condition : conditions)
        result.headers.push_back(condition.field);
    result.headers.push_back("Count");
    std::vector<std::string> row;
    for (const auto& condition : conditions)
        row.push_back(trim(condition.value));
    row.push_back(std::to_string(count));
    result.rows.push_back(std::move(row));
    result.sources.push_back(dataset.name);
    result.explanation =
        "Exact selected-value occurrence count.";
    return result;
}

QueryResult Engine::common_values(
        const std::string& identity_field,
        const std::string& first_identity,
        const std::string& second_identity,
        const std::string& value_field,
        const std::string& source_name) const {
    if (trim(identity_field).empty() ||
        trim(value_field).empty() ||
        trim(first_identity).empty() ||
        trim(second_identity).empty()) {
        throw std::runtime_error(
            "Comparison fields and both identities are required");
    }
    if (iequals_ascii(
            trim(first_identity), trim(second_identity))) {
        throw std::runtime_error(
            "Choose two different identities to compare");
    }

    const auto normalized_identity =
        canonical_field_name(identity_field);
    const auto normalized_value =
        canonical_field_name(value_field);
    std::vector<std::size_t> compatible_datasets;
    for (std::size_t dataset_id = 0;
         dataset_id < datasets_.size(); ++dataset_id) {
        if (!trim(source_name).empty() &&
            !iequals_ascii(
                datasets_[dataset_id].name, source_name)) {
            continue;
        }
        const auto& indexes =
            datasets_[dataset_id].normalized_header_index;
        if (indexes.contains(normalized_identity) &&
            indexes.contains(normalized_value)) {
            compatible_datasets.push_back(dataset_id);
        }
    }
    if (compatible_datasets.empty())
        throw std::runtime_error(
            "No single report contains both comparison fields");
    if (compatible_datasets.size() > 1) {
        std::string message =
            "Comparison fields are ambiguous because they occur together "
            "in multiple reports: ";
        for (std::size_t i = 0;
             i < compatible_datasets.size(); ++i) {
            if (i) message += ", ";
            message += datasets_[compatible_datasets[i]].name;
        }
        message +=
            ". Select a more specific identity or comparison field.";
        throw std::runtime_error(message);
    }

    const auto& dataset =
        datasets_[compatible_datasets.front()];
    const auto identity_column =
        dataset.normalized_header_index.at(normalized_identity);
    const auto value_column =
        dataset.normalized_header_index.at(normalized_value);
    std::map<std::string, std::string> first_values;
    std::map<std::string, std::string> second_values;
    bool first_found = false;
    bool second_found = false;

    for (const auto& row : dataset.rows) {
        if (identity_column >= row.size()) continue;
        const auto identity = trim(row[identity_column]);
        const bool belongs_to_first =
            iequals_ascii(identity, trim(first_identity));
        const bool belongs_to_second =
            iequals_ascii(identity, trim(second_identity));
        if (!belongs_to_first && !belongs_to_second) continue;
        if (belongs_to_first) first_found = true;
        if (belongs_to_second) second_found = true;
        if (value_column >= row.size()) continue;
        const auto value = trim(row[value_column]);
        if (value.empty()) continue;
        const auto key = normalize_name(value);
        if (belongs_to_first) first_values.try_emplace(key, value);
        if (belongs_to_second) second_values.try_emplace(key, value);
    }

    if (!first_found)
        throw std::runtime_error(
            "First identity was not found in the comparison report");
    if (!second_found)
        throw std::runtime_error(
            "Second identity was not found in the comparison report");

    QueryResult result;
    result.headers = {
        identity_field + " A",
        identity_field + " B",
        "Common " + value_field};
    for (const auto& [key, display_value] : first_values) {
        if (!second_values.contains(key)) continue;
        result.rows.push_back({
            trim(first_identity),
            trim(second_identity),
            display_value});
        if (result.rows.size() > limits_.max_result_rows)
            throw std::runtime_error(
                "Common-value result safety limit exceeded");
    }
    result.sources.push_back(dataset.name);
    result.explanation =
        "Exact intersection of normalized values for two identities.";
    return result;
}

QueryResult Engine::compare_values(
        const std::string& identity_field,
        const std::string& first_identity,
        const std::string& second_identity,
        const std::string& value_field,
        const std::string& source_name) const {
    if (trim(identity_field).empty() ||
        trim(value_field).empty() ||
        trim(first_identity).empty() ||
        trim(second_identity).empty()) {
        throw std::runtime_error(
            "Comparison fields and both identities are required");
    }
    if (iequals_ascii(
            trim(first_identity), trim(second_identity))) {
        throw std::runtime_error(
            "Choose two different identities to compare");
    }

    const auto normalized_identity =
        canonical_field_name(identity_field);
    const auto normalized_value =
        canonical_field_name(value_field);
    std::vector<std::size_t> compatible_datasets;
    for (std::size_t dataset_id = 0;
         dataset_id < datasets_.size(); ++dataset_id) {
        if (!trim(source_name).empty() &&
            !iequals_ascii(
                datasets_[dataset_id].name, source_name)) {
            continue;
        }
        const auto& indexes =
            datasets_[dataset_id].normalized_header_index;
        if (indexes.contains(normalized_identity) &&
            indexes.contains(normalized_value)) {
            compatible_datasets.push_back(dataset_id);
        }
    }
    if (compatible_datasets.empty())
        throw std::runtime_error(
            "No selected report contains both comparison fields");
    if (compatible_datasets.size() > 1)
        throw std::runtime_error(
            "Comparison fields occur together in multiple reports. "
            "Choose a source from Workspace > Next Source.");

    const auto& dataset =
        datasets_[compatible_datasets.front()];
    const auto identity_column =
        dataset.normalized_header_index.at(normalized_identity);
    const auto value_column =
        dataset.normalized_header_index.at(normalized_value);
    std::map<std::string, std::string> first_values;
    std::map<std::string, std::string> second_values;
    bool first_found = false;
    bool second_found = false;
    for (const auto& row : dataset.rows) {
        if (identity_column >= row.size()) continue;
        const auto identity = trim(row[identity_column]);
        const bool is_first =
            iequals_ascii(identity, trim(first_identity));
        const bool is_second =
            iequals_ascii(identity, trim(second_identity));
        if (!is_first && !is_second) continue;
        if (is_first) first_found = true;
        if (is_second) second_found = true;
        if (value_column >= row.size()) continue;
        const auto value = trim(row[value_column]);
        if (value.empty()) continue;
        const auto key = normalize_name(value);
        if (is_first) first_values.try_emplace(key, value);
        if (is_second) second_values.try_emplace(key, value);
    }
    if (!first_found)
        throw std::runtime_error(
            "First identity was not found in the comparison report");
    if (!second_found)
        throw std::runtime_error(
            "Second identity was not found in the comparison report");

    QueryResult result;
    result.headers = {"Result Type", value_field};
    // Keep comparison categories together so the result reads like a report:
    // every shared value first, then values unique to A, then values unique
    // to B. Each category remains alphabetically ordered by normalized value.
    for (const auto& [key, value] : first_values) {
        if (second_values.contains(key))
            result.rows.push_back({"Common", value});
    }
    for (const auto& [key, value] : first_values) {
        if (!second_values.contains(key))
            result.rows.push_back(
                {"Only " + trim(first_identity), value});
    }
    for (const auto& [key, value] : second_values) {
        if (!first_values.contains(key))
            result.rows.push_back(
                {"Only " + trim(second_identity), value});
    }
    if (result.rows.size() > limits_.max_result_rows)
        throw std::runtime_error(
            "Comparison result safety limit exceeded");
    result.sources.push_back(dataset.name);
    result.explanation =
        "Complete two-identity value comparison.";
    return result;
}

QueryResult Engine::compare_group_matrix(
        const std::string& identity_field,
        const std::vector<std::string>& identities) const {
    if (trim(identity_field).empty() || identities.size() < 2 ||
        identities.size() > 64) {
        throw std::runtime_error(
            "Group matrix requires one identity field and two to 64 users");
    }
    const auto normalized_identity_field =
        canonical_field_name(identity_field);
    std::set<std::string> seen_identities;
    std::vector<std::set<std::string>> display_names_by_user;
    std::vector<std::map<std::string, std::string>> groups_by_user(
        identities.size());
    std::map<std::string, std::string> all_groups;
    std::set<std::string> sources;
    QueryResult result;
    display_names_by_user.resize(identities.size());
    for (std::size_t user = 0; user < identities.size(); ++user) {
        const auto& raw_identity = identities[user];
        const auto identity = trim(raw_identity);
        if (identity.empty())
            throw std::runtime_error("Group matrix identities cannot be blank");
        if (!seen_identities.insert(normalize_name(identity)).second)
            throw std::runtime_error(
                "Each Group matrix identity must be different");
        for (std::size_t dataset_id = 0;
             dataset_id < datasets_.size(); ++dataset_id) {
            const auto& dataset = datasets_[dataset_id];
            const auto identity_column =
                dataset.normalized_header_index.find(
                    normalized_identity_field);
            if (identity_column ==
                dataset.normalized_header_index.end()) continue;
            std::optional<std::size_t> display_column;
            for (const auto& candidate : {
                     std::string("displayname"),
                     std::string("fullname"), std::string("name")}) {
                const auto found =
                    dataset.normalized_header_index.find(candidate);
                if (found != dataset.normalized_header_index.end()) {
                    display_column = found->second;
                    break;
                }
            }
            if (!display_column) continue;
            const auto& identity_index = exact_value_index(
                dataset_id, identity_column->second);
            const auto matching_rows = identity_index.find(
                indexed_value_key(dataset_id, identity_column->second,
                                  identity));
            if (matching_rows == identity_index.end()) continue;
            for (const auto row_id : matching_rows->second) {
                if (row_id >= dataset.rows.size() ||
                    *display_column >= dataset.rows[row_id].size()) continue;
                const auto display = trim(
                    dataset.rows[row_id][*display_column]);
                if (!display.empty())
                    display_names_by_user[user].insert(display);
            }
            sources.insert(dataset.name);
        }
        result.headers.push_back(identity);
        if (display_names_by_user[user].empty()) {
            // Retain compatibility with user-defined multi-hop identity
            // mappings. This fallback is used only when the fast same-row
            // identity-to-name resolution is unavailable.
            const auto resolved = universal_lookup(
                {identity_field, "Display Name"}, identity);
            for (const auto& row : resolved.rows) {
                if (row.size() > 1 && !trim(row[1]).empty())
                    display_names_by_user[user].insert(trim(row[1]));
            }
            sources.insert(resolved.sources.begin(), resolved.sources.end());
        }
        if (display_names_by_user[user].empty())
            throw std::runtime_error(
                "Group matrix identity was not found: " + identity);
        std::set<std::string> people;
        for (const auto& display : display_names_by_user[user]) {
            auto key = person_name_key(display);
            if (key.empty()) key = normalize_name(display);
            if (!key.empty()) people.insert(std::move(key));
        }
        if (people.size() > 1)
            throw std::runtime_error(
                "Group matrix identity maps to multiple Display Names: " +
                identity);
    }

    // Build/reuse each Members exact-token index once, then probe it for all
    // users. This avoids repeating the full relationship graph traversal for
    // every identity and makes work proportional to users x member columns.
    for (std::size_t dataset_id = 0;
         dataset_id < datasets_.size(); ++dataset_id) {
        const auto& dataset = datasets_[dataset_id];
        const auto group_column =
            dataset.normalized_header_index.find("groupname");
        if (group_column == dataset.normalized_header_index.end()) continue;
        for (std::size_t member_column = 0;
             member_column < dataset.headers.size(); ++member_column) {
            const auto original = normalize_name(
                dataset.headers[member_column]);
            if (original != "members" && original != "member" &&
                original != "membernames" &&
                original != "membersnames") continue;
            const auto& member_index = exact_value_index(
                dataset_id, member_column);
            for (std::size_t user = 0;
                 user < display_names_by_user.size(); ++user) {
                std::set<std::size_t> matching_group_rows;
                for (const auto& display : display_names_by_user[user]) {
                    for (const auto& key : indexed_field_values(
                             "displayname", display)) {
                        const auto found = member_index.find(key);
                        if (found == member_index.end()) continue;
                        matching_group_rows.insert(
                            found->second.begin(), found->second.end());
                    }
                }
                for (const auto row_id : matching_group_rows) {
                    if (row_id >= dataset.rows.size() ||
                        group_column->second >=
                            dataset.rows[row_id].size()) continue;
                    const auto group = trim(
                        dataset.rows[row_id][group_column->second]);
                    if (group.empty()) continue;
                    const auto key = normalize_name(group);
                    groups_by_user[user].try_emplace(key, group);
                    all_groups.try_emplace(key, group);
                    sources.insert(dataset.name);
                }
            }
        }
    }
    for (const auto& [key, display] : all_groups) {
        std::vector<std::string> row(groups_by_user.size());
        for (std::size_t user = 0; user < groups_by_user.size(); ++user) {
            const auto found = groups_by_user[user].find(key);
            if (found != groups_by_user[user].end()) row[user] = found->second;
        }
        result.rows.push_back(std::move(row));
        if (result.rows.size() > limits_.max_result_rows)
            throw std::runtime_error(
                "Group matrix result safety limit exceeded");
    }
    result.sources.assign(sources.begin(), sources.end());
    result.explanation =
        "Batched exact multi-user group membership matrix. Identity rows and "
        "member indexes are reused; blank cells mean that user is not a member.";
    return result;
}

QueryResult Engine::compare_profiles(
        const std::string& identity_field,
        const std::string& first_identity,
        const std::string& second_identity,
        const std::vector<std::string>& value_fields,
        const std::string& source_name) const {
    const auto identity_a = trim(first_identity);
    const auto identity_b = trim(second_identity);
    if (trim(identity_field).empty() || identity_a.empty() ||
        identity_b.empty() || value_fields.empty() ||
        value_fields.size() > 5) {
        throw std::runtime_error(
            "Compare requires an identity field, two identities, and "
            "one to five comparison fields");
    }
    if (iequals_ascii(identity_a, identity_b))
        throw std::runtime_error(
            "Choose two different identities to compare");

    // Group membership is inherently cross-report: identities and Display
    // Names live in the employee report while Group Name and Members live in
    // the group report. Use the deterministic Universal membership path for
    // each identity, then compare the resulting group sets.
    if (value_fields.size() == 1 &&
        canonical_field_name(value_fields.front()) == "groupname") {
        auto groups_for = [&](const std::string& identity) {
            const auto membership = universal_lookup(
                {identity_field, "Display Name", "Group Name"}, identity);
            if (membership.rows.empty())
                throw std::runtime_error(
                    "Compare identity was not found: " + identity);
            std::map<std::string, std::string> groups;
            for (const auto& row : membership.rows) {
                if (row.size() < 3) continue;
                const auto group = trim(row[2]);
                if (group.empty()) continue;
                groups.try_emplace(normalize_name(group), group);
            }
            return std::pair{std::move(groups), membership.sources};
        };
        auto [first_groups, first_sources] = groups_for(identity_a);
        auto [second_groups, second_sources] = groups_for(identity_b);
        std::map<std::string, std::string> all_groups = first_groups;
        for (const auto& [key, display] : second_groups)
            all_groups.try_emplace(key, display);

        QueryResult membership_comparison;
        membership_comparison.headers = {
            "Group Name", "Result", "Users in Group",
            "Users Not in Group"};
        auto add_category = [&](bool common) {
            for (const auto& [key, display] : all_groups) {
                const bool first_has = first_groups.contains(key);
                const bool second_has = second_groups.contains(key);
                if ((first_has && second_has) != common) continue;
                std::string present;
                std::string missing;
                auto append = [](std::string& target,
                                 const std::string& value) {
                    if (!target.empty()) target += "; ";
                    target += value;
                };
                if (first_has) append(present, identity_a);
                else append(missing, identity_a);
                if (second_has) append(present, identity_b);
                else append(missing, identity_b);
                membership_comparison.rows.push_back({
                    display, common ? "Common" : "Not Common",
                    present, missing});
            }
        };
        add_category(true);
        add_category(false);
        if (membership_comparison.rows.size() > limits_.max_result_rows)
            throw std::runtime_error(
                "Group comparison result safety limit exceeded");
        std::set<std::string> sources(
            first_sources.begin(), first_sources.end());
        sources.insert(second_sources.begin(), second_sources.end());
        membership_comparison.sources.assign(
            sources.begin(), sources.end());
        membership_comparison.explanation =
            "Exact cross-report group membership comparison.";
        return membership_comparison;
    }

    std::set<std::string> requested_fields;
    for (const auto& field : value_fields) {
        const auto normalized = canonical_field_name(field);
        if (normalized.empty())
            throw std::runtime_error(
                "Comparison field names cannot be blank");
        if (!requested_fields.insert(normalized).second)
            throw std::runtime_error(
                "Choose each comparison field only once");
    }

    struct Evidence {
        std::string display;
        std::set<std::string> sources;
    };
    struct FieldEvidence {
        std::map<std::string, Evidence> first;
        std::map<std::string, Evidence> second;
        std::set<std::string> sources;
        bool compatible = false;
    };
    std::vector<FieldEvidence> evidence(value_fields.size());
    bool first_found = false;
    bool second_found = false;
    const auto normalized_identity = canonical_field_name(identity_field);

    for (std::size_t field_id = 0;
         field_id < value_fields.size(); ++field_id) {
        const auto normalized_value =
            canonical_field_name(value_fields[field_id]);
        for (const auto& dataset : datasets_) {
            if (!trim(source_name).empty() &&
                !iequals_ascii(dataset.name, source_name)) {
                continue;
            }
            const auto& indexes = dataset.normalized_header_index;
            if (!indexes.contains(normalized_identity) ||
                !indexes.contains(normalized_value)) {
                continue;
            }
            evidence[field_id].compatible = true;
            evidence[field_id].sources.insert(dataset.name);
            const auto identity_column =
                indexes.at(normalized_identity);
            const auto value_column = indexes.at(normalized_value);
            for (const auto& row : dataset.rows) {
                if (identity_column >= row.size()) continue;
                const auto identity = trim(row[identity_column]);
                const bool is_first =
                    iequals_ascii(identity, identity_a);
                const bool is_second =
                    iequals_ascii(identity, identity_b);
                if (!is_first && !is_second) continue;
                if (is_first) first_found = true;
                if (is_second) second_found = true;
                if (value_column >= row.size()) continue;
                const auto value = trim(row[value_column]);
                if (value.empty()) continue;
                const auto key = normalize_name(value);
                auto& values = is_first
                    ? evidence[field_id].first
                    : evidence[field_id].second;
                auto [position, inserted] =
                    values.try_emplace(key, Evidence{value, {}});
                if (!inserted && position->second.display.empty())
                    position->second.display = value;
                position->second.sources.insert(dataset.name);
            }
        }
        if (!evidence[field_id].compatible)
            throw std::runtime_error(
                "No selected report contains both '" +
                trim(identity_field) + "' and '" +
                trim(value_fields[field_id]) + "'");
    }
    if (!first_found)
        throw std::runtime_error(
            "First identity was not found in compatible reports");
    if (!second_found)
        throw std::runtime_error(
            "Second identity was not found in compatible reports");

    auto joined_sources = [](const std::set<std::string>& sources) {
        std::string joined;
        for (const auto& source : sources) {
            if (!joined.empty()) joined += ", ";
            joined += source;
        }
        return joined;
    };
    auto sensitivity = [](const std::string& field,
                          const std::string& value) {
        const auto text = normalize_name(field + " " + value);
        static const std::vector<std::string> high = {
            "admin", "administrator", "privileged", "root",
            "cyberark", "vault", "domain", "global", "breakglass",
            "owner", "fullcontrol", "write", "modify"};
        static const std::vector<std::string> medium = {
            "vpn", "remote", "aws", "azure", "cloud", "console",
            "mfa", "critical", "high", "serviceaccount"};
        for (const auto& token : high)
            if (text.find(token) != std::string::npos) return 2;
        for (const auto& token : medium)
            if (text.find(token) != std::string::npos) return 1;
        return 0;
    };

    QueryResult result;
    result.headers = {
        "Field", "Result Type", "Value", "Source Reports",
        "Risk", "Recommended Action"};
    std::size_t common_count = 0;
    std::size_t union_count = 0;
    int highest_asymmetric_risk = 0;
    std::set<std::string> all_sources;
    for (std::size_t field_id = 0;
         field_id < value_fields.size(); ++field_id) {
        const auto& field = evidence[field_id];
        all_sources.insert(field.sources.begin(), field.sources.end());
        for (const auto& [key, value] : field.first) {
            ++union_count;
            if (field.second.contains(key)) ++common_count;
            else highest_asymmetric_risk = std::max(
                highest_asymmetric_risk,
                sensitivity(value_fields[field_id], value.display));
        }
        for (const auto& [key, value] : field.second) {
            if (field.first.contains(key)) continue;
            ++union_count;
            highest_asymmetric_risk = std::max(
                highest_asymmetric_risk,
                sensitivity(value_fields[field_id], value.display));
        }
    }
    const auto similarity = union_count == 0 ? 100 :
        static_cast<int>(std::lround(
            100.0 * static_cast<double>(common_count) /
            static_cast<double>(union_count)));
    const std::string summary_risk =
        highest_asymmetric_risk == 2 ? "High" :
        highest_asymmetric_risk == 1 ? "Medium" :
        common_count == union_count ? "Info" : "Low";
    result.rows.push_back({
        "Overall", "Similarity",
        std::to_string(similarity) + "% (" +
            std::to_string(common_count) + " common / " +
            std::to_string(union_count) + " unique)",
        std::to_string(all_sources.size()) + " report(s)",
        summary_risk,
        highest_asymmetric_risk == 2
            ? "Review asymmetric privileged access immediately."
            : highest_asymmetric_risk == 1
            ? "Validate asymmetric access and owner approval."
            : common_count == union_count
            ? "Profiles match for the selected evidence."
            : "Confirm differences are justified by role."});

    auto append_row = [&](const std::string& field,
                          const std::string& category,
                          const Evidence& item,
                          const std::set<std::string>& sources,
                          bool common) {
        const int level = sensitivity(field, item.display);
        const std::string risk = common
            ? (level == 2 ? "Medium" : "Info")
            : (level == 2 ? "High" :
               level == 1 ? "Medium" : "Low");
        const std::string action = common
            ? (level == 2
                ? "Confirm both identities still require this "
                  "shared sensitive access."
                : "Shared value; retain only while required by both roles.")
            : (level == 2
                ? "Remove or document approved privileged-access exception."
                : level == 1
                ? "Validate business need, owner approval, and scope."
                : "Confirm this difference is role-based.");
        result.rows.push_back({
            field, category, item.display, joined_sources(sources),
            risk, action});
        if (result.rows.size() > limits_.max_result_rows)
            throw std::runtime_error(
                "Advanced comparison result safety limit exceeded");
    };

    for (std::size_t field_id = 0;
         field_id < value_fields.size(); ++field_id) {
        const auto& field = evidence[field_id];
        for (const auto& [key, value] : field.first) {
            const auto match = field.second.find(key);
            if (match == field.second.end()) continue;
            auto sources = value.sources;
            sources.insert(
                match->second.sources.begin(),
                match->second.sources.end());
            append_row(
                value_fields[field_id], "Common", value, sources, true);
        }
        for (const auto& [key, value] : field.first) {
            if (!field.second.contains(key))
                append_row(
                    value_fields[field_id], "Only " + identity_a,
                    value, value.sources, false);
        }
        for (const auto& [key, value] : field.second) {
            if (!field.first.contains(key))
                append_row(
                    value_fields[field_id], "Only " + identity_b,
                    value, value.sources, false);
        }
    }
    result.sources.assign(all_sources.begin(), all_sources.end());
    result.explanation =
        "Multi-report identity comparison with deduplicated evidence, "
        "Jaccard similarity, source lineage, and access-risk guidance.";
    return result;
}

QueryResult Engine::analyze_field(
        const std::string& field,
        const std::string& source_name) const {
    if (trim(field).empty())
        throw std::runtime_error(
            "Type one field to analyze");
    const auto normalized = canonical_field_name(field);
    std::vector<std::size_t> compatible_datasets;
    for (std::size_t dataset_id = 0;
         dataset_id < datasets_.size(); ++dataset_id) {
        if (!trim(source_name).empty() &&
            !iequals_ascii(
                datasets_[dataset_id].name, source_name)) {
            continue;
        }
        if (datasets_[dataset_id]
                .normalized_header_index.contains(normalized)) {
            compatible_datasets.push_back(dataset_id);
        }
    }
    if (compatible_datasets.empty())
        throw std::runtime_error(
            "The selected field was not found in the selected source");
    if (compatible_datasets.size() > 1)
        throw std::runtime_error(
            "The analysis field occurs in multiple reports. "
            "Choose a source from Workspace > Next Source.");

    const auto& dataset =
        datasets_[compatible_datasets.front()];
    const auto column =
        dataset.normalized_header_index.at(normalized);
    std::map<std::string, std::pair<std::string, std::size_t>> counts;
    std::size_t missing = 0;
    for (const auto& row : dataset.rows) {
        const auto value =
            column < row.size() ? trim(row[column]) : std::string{};
        if (value.empty()) {
            ++missing;
            continue;
        }
        const auto key = normalize_name(value);
        auto& entry = counts[key];
        if (entry.first.empty()) entry.first = value;
        ++entry.second;
    }

    QueryResult result;
    result.headers = {"Issue Type", field, "Count"};
    if (missing)
        result.rows.push_back(
            {"Missing", "(blank)", std::to_string(missing)});
    for (const auto& [key, entry] : counts) {
        (void)key;
        if (entry.second > 1) {
            result.rows.push_back({
                "Duplicate", entry.first,
                std::to_string(entry.second)});
        }
    }
    if (result.rows.empty())
        result.rows.push_back({"Clean", "", "0"});
    result.sources.push_back(dataset.name);
    result.explanation =
        "Duplicate and missing-value analysis.";
    return result;
}

QueryResult Engine::analyze_keys(
        const std::vector<std::string>& key_fields,
        const std::string& source_name,
        const std::vector<std::string>& exact_key_values) const {
    if (key_fields.empty() || key_fields.size() > 3)
        throw std::runtime_error(
            "Analyze mode requires one to three key fields");

    std::vector<std::string> normalized_keys;
    if (!exact_key_values.empty() &&
        exact_key_values.size() != key_fields.size()) {
        throw std::runtime_error(
            "Analyze filters must align with the selected key fields");
    }
    std::vector<std::string> normalized_filters(
        key_fields.size());
    for (std::size_t i = 0;
         i < exact_key_values.size(); ++i) {
        normalized_filters[i] =
            normalize_name(exact_key_values[i]);
    }
    std::set<std::string> unique_keys;
    for (const auto& field : key_fields) {
        const auto normalized = canonical_field_name(field);
        if (normalized.empty())
            throw std::runtime_error(
                "Analyze key fields cannot be blank");
        if (!unique_keys.insert(normalized).second)
            throw std::runtime_error(
                "Analyze key fields must be different");
        normalized_keys.push_back(normalized);
    }

    std::vector<std::size_t> compatible_datasets;
    for (std::size_t dataset_id = 0;
         dataset_id < datasets_.size(); ++dataset_id) {
        const auto& dataset = datasets_[dataset_id];
        if (!trim(source_name).empty() &&
            !iequals_ascii(dataset.name, source_name)) {
            continue;
        }
        bool compatible = true;
        for (const auto& key : normalized_keys) {
            if (!dataset.normalized_header_index.contains(key)) {
                compatible = false;
                break;
            }
        }
        if (compatible) compatible_datasets.push_back(dataset_id);
    }
    if (compatible_datasets.empty())
        throw std::runtime_error(
            "No selected report contains every Analyze key field");

    struct Occurrence {
        std::string key_display;
        std::string source;
        std::size_t parsed_row = 0;
        std::string details;
        std::string signature;
    };
    std::map<std::string, std::vector<Occurrence>> groups;
    std::vector<Occurrence> missing;
    std::set<std::string> sources;

    for (const auto dataset_id : compatible_datasets) {
        const auto& dataset = datasets_[dataset_id];
        sources.insert(dataset.name);
        std::vector<std::size_t> key_columns;
        for (const auto& key : normalized_keys)
            key_columns.push_back(
                dataset.normalized_header_index.at(key));

        for (std::size_t row_id = 0;
             row_id < dataset.rows.size(); ++row_id) {
            const auto& row = dataset.rows[row_id];
            std::string normalized_composite;
            std::string display_composite;
            bool missing_component = false;
            bool filter_match = true;
            for (std::size_t i = 0; i < key_columns.size(); ++i) {
                const auto column = key_columns[i];
                const auto value =
                    column < row.size() ? trim(row[column])
                                        : std::string{};
                if (i) {
                    normalized_composite.push_back('\x1f');
                    display_composite += " | ";
                }
                normalized_composite += normalize_name(value);
                if (!normalized_filters[i].empty() &&
                    normalize_name(value) != normalized_filters[i]) {
                    filter_match = false;
                }
                display_composite +=
                    key_fields[i] + "=" +
                    (value.empty() ? "(blank)" : value);
                if (value.empty()) missing_component = true;
            }
            if (!filter_match) continue;

            std::string details;
            std::string signature;
            for (std::size_t column = 0;
                 column < dataset.headers.size(); ++column) {
                const auto value =
                    column < row.size() ? trim(row[column])
                                        : std::string{};
                if (column) signature.push_back('\x1e');
                signature += normalize_name(dataset.headers[column]);
                signature.push_back('=');
                signature += value;
                if (details.size() < 4096) {
                    if (!details.empty()) details += "; ";
                    details += dataset.headers[column] + "=" + value;
                }
                if (details.size() > 4096) {
                    details.resize(4093);
                    details += "...";
                }
            }
            Occurrence occurrence{
                display_composite, dataset.name, row_id + 2,
                details, signature};
            if (missing_component)
                missing.push_back(std::move(occurrence));
            else
                groups[normalized_composite].push_back(
                    std::move(occurrence));
        }
    }

    QueryResult result;
    result.headers = {
        "Issue Type", "Key", "Source", "Parsed Row",
        "Record Details", "Occurrences"};
    auto append = [&result, this](
            const std::string& issue,
            const Occurrence& occurrence,
            std::size_t count) {
        if (result.rows.size() >= limits_.max_result_rows)
            throw std::runtime_error(
                "Analyze result safety limit exceeded");
        result.rows.push_back({
            issue, occurrence.key_display, occurrence.source,
            std::to_string(occurrence.parsed_row),
            occurrence.details, std::to_string(count)});
    };
    for (const auto& occurrence : missing)
        append("Missing Key", occurrence, 1);
    for (const auto& [key, occurrences] : groups) {
        (void)key;
        if (occurrences.size() < 2) continue;
        const auto& first_signature = occurrences.front().signature;
        const bool exact = std::all_of(
            occurrences.begin(), occurrences.end(),
            [&first_signature](const Occurrence& occurrence) {
                return occurrence.signature == first_signature;
            });
        const auto issue =
            exact ? "Exact Duplicate Row"
                  : "Repeated Key Records (Different Details)";
        for (const auto& occurrence : occurrences)
            append(issue, occurrence, occurrences.size());
    }
    if (result.rows.empty()) {
        result.rows.push_back({
            "Clean", "", trim(source_name).empty() ? "All compatible reports"
                                                    : source_name,
            "", "No duplicate or missing key records found", "0"});
    }
    result.sources.assign(sources.begin(), sources.end());
    result.explanation =
        "Detailed repeated-key and missing-key record analysis.";
    return result;
}

QueryResult Engine::deep_insights(
        const std::vector<std::string>& fields,
        const std::string& source_name) const {
    QueryResult result;
    result.headers = {
        "Priority", "Source / Field", "Insight", "Evidence",
        "Score", "Recommended Action"};

    std::vector<std::string> normalized_fields;
    std::set<std::string> unique_fields;
    for (const auto& field : fields) {
        const auto normalized = canonical_field_name(field);
        if (normalized.empty() ||
            !unique_fields.insert(normalized).second) {
            throw std::runtime_error(
                "Insight fields must be nonblank and different");
        }
        normalized_fields.push_back(normalized);
    }

    auto add_finding = [&](const std::string& priority,
                           const DataSet& dataset,
                           const std::string& field,
                           const std::string& insight,
                           const std::string& evidence,
                           int score,
                           const std::string& action) {
        if (result.rows.size() >= limits_.max_result_rows)
            throw std::runtime_error(
                "Insight result safety limit exceeded");
        result.rows.push_back({
            priority, dataset.name + " / " + field, insight, evidence,
            std::to_string(std::clamp(score, 0, 100)), action});
    };

    bool any_dataset = false;
    for (const auto& dataset : datasets_) {
        if (!trim(source_name).empty() &&
            !iequals_ascii(dataset.name, source_name)) {
            continue;
        }
        std::vector<std::size_t> columns;
        if (normalized_fields.empty()) {
            for (std::size_t i = 0; i < dataset.headers.size(); ++i)
                columns.push_back(i);
        } else {
            bool compatible = true;
            for (const auto& field : normalized_fields) {
                const auto it =
                    dataset.normalized_header_index.find(field);
                if (it == dataset.normalized_header_index.end()) {
                    compatible = false;
                    break;
                }
                columns.push_back(it->second);
            }
            if (!compatible) continue;
        }
        any_dataset = true;
        result.sources.push_back(dataset.name);
        for (const auto column : columns) {
            const auto& field = dataset.headers[column];
            const std::size_t total = dataset.rows.size();
            std::size_t missing = 0;
            std::map<std::string, std::pair<std::string, std::size_t>>
                frequencies;
            std::vector<double> numbers;
            numbers.reserve(total);
            for (const auto& row : dataset.rows) {
                const auto value =
                    column < row.size() ? trim(row[column])
                                        : std::string{};
                if (value.empty()) {
                    ++missing;
                    continue;
                }
                auto& entry = frequencies[normalize_name(value)];
                if (entry.first.empty()) entry.first = value;
                ++entry.second;
                char* end = nullptr;
                const double number = std::strtod(value.c_str(), &end);
                if (end && *end == '\0' && std::isfinite(number))
                    numbers.push_back(number);
            }
            const std::size_t populated = total - missing;
            std::size_t top_count = 0;
            std::string top_value;
            for (const auto& [key, entry] : frequencies) {
                (void)key;
                if (entry.second > top_count) {
                    top_count = entry.second;
                    top_value = entry.first;
                }
            }
            const std::size_t duplicate_excess =
                populated > frequencies.size()
                ? populated - frequencies.size() : 0;
            const double missing_ratio =
                total ? static_cast<double>(missing) / total : 0.0;
            const double unique_ratio =
                populated
                ? static_cast<double>(frequencies.size()) / populated
                : 0.0;
            const double top_ratio =
                populated
                ? static_cast<double>(top_count) / populated : 0.0;
            const auto normalized_field = canonical_field_name(field);
            const bool identifier_like =
                normalized_field == "id" ||
                normalized_field.ends_with("id") ||
                normalized_field.find("identifier") != std::string::npos ||
                normalized_field.find("username") != std::string::npos ||
                normalized_field.find("email") != std::string::npos ||
                normalized_field.find("asset") != std::string::npos;

            if (total == 0) {
                add_finding(
                    "High", dataset, field, "Empty report",
                    "No data rows", 100,
                    "Confirm the export completed and refresh the report.");
                continue;
            }
            if (missing > 0) {
                const int score = static_cast<int>(
                    std::round(missing_ratio * 100.0));
                add_finding(
                    missing_ratio >= 0.20 ? "High" :
                    missing_ratio >= 0.05 ? "Medium" : "Low",
                    dataset, field, "Missing values",
                    std::to_string(missing) + " of " +
                    std::to_string(total) + " rows (" +
                    std::to_string(score) + "%)",
                    std::max(10, score),
                    identifier_like
                    ? "Review source ownership; identifiers should be complete."
                    : "Confirm whether blanks are expected or need enrichment.");
            }
            if (identifier_like && duplicate_excess > 0) {
                const int score = std::min(
                    100, 60 + static_cast<int>(
                        40.0 * duplicate_excess /
                        std::max<std::size_t>(1, populated)));
                add_finding(
                    "High", dataset, field,
                    "Possible duplicate identifiers",
                    std::to_string(duplicate_excess) +
                    " repeated populated row(s)", score,
                    "Run Analyze with this field as the key and review records.");
            } else if (duplicate_excess > 0) {
                add_finding(
                    "Info", dataset, field, "Repeated values",
                    std::to_string(frequencies.size()) +
                    " distinct across " + std::to_string(populated) +
                    " populated rows", 20,
                    "Use Count or Chart to inspect the distribution.");
            }
            if (top_ratio >= 0.80 && populated >= 5) {
                const int score =
                    static_cast<int>(std::round(top_ratio * 100.0));
                add_finding(
                    "Medium", dataset, field,
                    "Highly concentrated value",
                    top_value + " represents " +
                    std::to_string(score) + "% of populated rows",
                    score,
                    "Confirm this concentration is expected and not a default.");
            }
            if (unique_ratio == 1.0 && populated >= 2) {
                add_finding(
                    identifier_like ? "Info" : "Low",
                    dataset, field, "Every populated value is unique",
                    std::to_string(populated) + " unique values",
                    identifier_like ? 5 : 30,
                    identifier_like
                    ? "This field is a strong candidate relationship key."
                    : "Avoid grouping charts on this high-cardinality field.");
            }

            if (populated >= 2 &&
                numbers.size() * 10 >= populated * 9) {
                std::sort(numbers.begin(), numbers.end());
                const auto percentile = [&numbers](double p) {
                    const auto index = static_cast<std::size_t>(
                        p * static_cast<double>(numbers.size() - 1));
                    return numbers[index];
                };
                const double q1 = percentile(0.25);
                const double median = percentile(0.50);
                const double q3 = percentile(0.75);
                const double iqr = q3 - q1;
                const double low = q1 - 1.5 * iqr;
                const double high = q3 + 1.5 * iqr;
                const auto outliers = static_cast<std::size_t>(
                    std::count_if(
                        numbers.begin(), numbers.end(),
                        [low, high](double value) {
                            return value < low || value > high;
                        }));
                std::ostringstream evidence;
                evidence << "min=" << numbers.front()
                         << "; median=" << median
                         << "; max=" << numbers.back();
                add_finding(
                    "Info", dataset, field, "Numeric profile",
                    evidence.str(), 10,
                    "Use the chart to review range and distribution.");
                if (numbers.size() >= 4 && outliers > 0) {
                    add_finding(
                        "Medium", dataset, field,
                        "Statistical outliers",
                        std::to_string(outliers) +
                        " value(s) outside the 1.5×IQR range",
                        std::min(100, 40 +
                            static_cast<int>(outliers * 5)),
                        "Validate outliers against the source system.");
                }
            }
        }
    }
    if (!any_dataset)
        throw std::runtime_error(
            "No selected report contains every requested Insight field");
    if (result.rows.empty()) {
        result.rows.push_back({
            "Info", trim(source_name).empty()
                ? "All compatible reports" : source_name,
            "No notable findings", "Selected data passed current checks",
            "0", "No immediate action is recommended."});
    }
    const auto priority_rank = [](const std::string& priority) {
        if (priority == "High") return 0;
        if (priority == "Medium") return 1;
        if (priority == "Low") return 2;
        return 3;
    };
    std::stable_sort(
        result.rows.begin(), result.rows.end(),
        [&priority_rank](const auto& left, const auto& right) {
            const int left_rank = priority_rank(left[0]);
            const int right_rank = priority_rank(right[0]);
            if (left_rank != right_rank)
                return left_rank < right_rank;
            return std::stoi(left[4]) > std::stoi(right[4]);
        });
    result.explanation =
        "Point Insight Agent: deterministic local profiling and risk ranking.";
    return result;
}

QueryResult Engine::distribution(
        const std::string& category_field,
        const std::vector<QueryCondition>& filters,
        const std::string& source_name) const {
    return distribution(
        std::vector<std::string>{category_field}, filters, source_name);
}

QueryResult Engine::distribution(
        const std::vector<std::string>& category_fields,
        const std::vector<QueryCondition>& filters,
        const std::string& source_name) const {
    if (category_fields.empty() || category_fields.size() > 3)
        throw std::runtime_error(
            "Chart mode requires one to three category fields");
    std::vector<std::string> normalized_categories;
    std::set<std::string> unique_categories;
    for (const auto& field : category_fields) {
        const auto normalized = canonical_field_name(field);
        if (normalized.empty())
            throw std::runtime_error(
                "Chart category fields cannot be blank");
        if (!unique_categories.insert(normalized).second)
            throw std::runtime_error(
                "Chart category fields must be different");
        normalized_categories.push_back(normalized);
    }

    std::vector<std::size_t> compatible;
    for (std::size_t dataset_id = 0;
         dataset_id < datasets_.size(); ++dataset_id) {
        const auto& dataset = datasets_[dataset_id];
        if (!trim(source_name).empty() &&
            !iequals_ascii(dataset.name, source_name)) {
            continue;
        }
        bool has_categories = true;
        for (const auto& category : normalized_categories)
            if (!dataset.normalized_header_index.contains(category)) {
                has_categories = false;
                break;
            }
        if (!has_categories) continue;
        bool has_filters = true;
        for (const auto& filter : filters) {
            if (!dataset.normalized_header_index.contains(
                    normalize_name(filter.field))) {
                has_filters = false;
                break;
            }
        }
        if (has_filters) compatible.push_back(dataset_id);
    }
    if (compatible.empty())
        throw std::runtime_error(
            "No selected report contains the chart category and filters");
    if (compatible.size() > 1)
        throw std::runtime_error(
            "Chart fields occur together in multiple reports. "
            "Choose a source from Workspace > Next Source.");

    const auto& dataset = datasets_[compatible.front()];
    std::vector<std::size_t> category_columns;
    for (const auto& category : normalized_categories)
        category_columns.push_back(
            dataset.normalized_header_index.at(category));
    std::vector<std::pair<std::size_t, std::string>> filter_columns;
    for (const auto& filter : filters) {
        if (trim(filter.value).empty())
            throw std::runtime_error(
                "Every selected Chart filter requires an exact value");
        filter_columns.push_back({
            dataset.normalized_header_index.at(
                normalize_name(filter.field)),
            trim(filter.value)});
    }

    struct GroupCount {
        std::vector<std::string> display_values;
        std::size_t count = 0;
    };
    std::map<std::string, GroupCount> counts;
    for (const auto& row : dataset.rows) {
        bool matches = true;
        for (const auto& [column, expected] : filter_columns) {
            const auto actual =
                column < row.size() ? trim(row[column])
                                    : std::string{};
            if (!iequals_ascii(actual, expected)) {
                matches = false;
                break;
            }
        }
        if (!matches) continue;
        std::vector<std::string> display_values;
        std::string key;
        for (const auto column : category_columns) {
            const auto value = column < row.size()
                ? trim(row[column]) : std::string{};
            const auto display = value.empty() ? "(blank)" : value;
            if (!key.empty()) key.push_back('\x1f');
            key += normalize_name(display);
            display_values.push_back(display);
        }
        auto& entry = counts[key];
        if (entry.display_values.empty())
            entry.display_values = std::move(display_values);
        ++entry.count;
    }

    QueryResult result;
    result.headers = category_fields;
    result.headers.push_back("Count");
    for (const auto& [key, entry] : counts) {
        (void)key;
        auto output = entry.display_values;
        output.push_back(std::to_string(entry.count));
        result.rows.push_back(std::move(output));
    }
    std::stable_sort(
        result.rows.begin(), result.rows.end(),
        [](const auto& left, const auto& right) {
            const auto left_count = static_cast<std::size_t>(
                std::stoull(left.back()));
            const auto right_count = static_cast<std::size_t>(
                std::stoull(right.back()));
            if (left_count != right_count)
                return left_count > right_count;
            return left < right;
        });
    if (result.rows.size() > limits_.max_result_rows)
        throw std::runtime_error(
            "Chart distribution safety limit exceeded");
    result.sources.push_back(dataset.name);
    result.explanation =
        "Exact filtered multi-field distribution for dynamic visualization.";
    return result;
}

QueryResult Engine::changes_since(
        const Engine& previous,
        const std::vector<std::string>& key_fields,
        const std::string& source_name) const {
    if (key_fields.empty() || key_fields.size() > 3)
        throw std::runtime_error(
            "Change mode requires one to three key fields");
    std::vector<std::string> normalized_keys;
    std::set<std::string> seen_keys;
    for (const auto& field : key_fields) {
        const auto normalized = canonical_field_name(field);
        if (normalized.empty() ||
            !seen_keys.insert(normalized).second)
            throw std::runtime_error(
                "Change key fields must be nonblank and different");
        normalized_keys.push_back(normalized);
    }

    QueryResult result;
    result.headers = {
        "Change Type", "Key", "Source / Parsed Row", "Changed Field",
        "Before", "After"};
    std::map<std::string, const DataSet*> old_by_name;
    for (const auto& dataset : previous.datasets_)
        old_by_name[normalize_name(dataset.name)] = &dataset;

    bool compared_any = false;
    std::size_t ambiguous_keys_skipped = 0;
    for (const auto& current : datasets_) {
        if (!trim(source_name).empty() &&
            !iequals_ascii(current.name, source_name))
            continue;
        const auto old_it =
            old_by_name.find(normalize_name(current.name));
        if (old_it == old_by_name.end()) continue;
        const auto& old = *old_it->second;
        bool compatible = true;
        for (const auto& key : normalized_keys) {
            if (!current.normalized_header_index.contains(key) ||
                !old.normalized_header_index.contains(key)) {
                compatible = false;
                break;
            }
        }
        if (!compatible) continue;
        compared_any = true;
        result.sources.push_back(current.name);

        struct Record {
            const std::vector<std::string>* row = nullptr;
            std::string display_key;
            std::size_t occurrences = 0;
            std::size_t parsed_row = 0;
        };
        auto index_rows = [&](const DataSet& dataset) {
            std::map<std::string, Record> index;
            for (std::size_t row_id = 0;
                 row_id < dataset.rows.size(); ++row_id) {
                const auto& row = dataset.rows[row_id];
                std::string key;
                std::string display;
                bool missing = false;
                for (std::size_t i = 0;
                     i < normalized_keys.size(); ++i) {
                    const auto column =
                        dataset.normalized_header_index.at(
                            normalized_keys[i]);
                    const auto value =
                        column < row.size() ? trim(row[column])
                                            : std::string{};
                    if (i) {
                        key.push_back('\x1f');
                        display += " | ";
                    }
                    key += normalize_name(value);
                    display += key_fields[i] + "=" +
                        (value.empty() ? "(blank)" : value);
                    if (value.empty()) missing = true;
                }
                if (missing) continue;
                auto& record = index[key];
                if (!record.row) {
                    record.row = &row;
                    record.display_key = display;
                    // Parsed row 1 is the report heading.
                    record.parsed_row = row_id + 2;
                }
                ++record.occurrences;
            }
            return index;
        };
        const auto old_rows = index_rows(old);
        const auto current_rows = index_rows(current);
        std::set<std::string> all_keys;
        for (const auto& [key, value] : old_rows) {
            (void)value;
            all_keys.insert(key);
        }
        for (const auto& [key, value] : current_rows) {
            (void)value;
            all_keys.insert(key);
        }
        for (const auto& key : all_keys) {
            const auto before_it = old_rows.find(key);
            const auto after_it = current_rows.find(key);
            const Record* before =
                before_it == old_rows.end() ? nullptr : &before_it->second;
            const Record* after =
                after_it == current_rows.end() ? nullptr : &after_it->second;
            const auto display_key =
                after ? after->display_key : before->display_key;
            if ((before && before->occurrences > 1) ||
                (after && after->occurrences > 1)) {
                const auto before_count = before ? before->occurrences : 0;
                const auto after_count = after ? after->occurrences : 0;
                if (before_count != after_count) {
                    result.rows.push_back({
                        "Duplicate Count Changed", display_key,
                        current.name + " / multiple rows",
                        "Key occurrence count",
                        std::to_string(before_count),
                        std::to_string(after_count)});
                } else {
                    ++ambiguous_keys_skipped;
                }
                continue;
            }
            if (!before) {
                bool emitted = false;
                for (std::size_t column = 0;
                     column < current.headers.size(); ++column) {
                    const auto normalized = canonical_field_name(
                        current.headers[column]);
                    if (seen_keys.contains(normalized)) continue;
                    const auto value = column < after->row->size()
                        ? trim((*after->row)[column]) : std::string{};
                    if (value.empty()) continue;
                    result.rows.push_back({
                        "Added", display_key,
                        current.name + " / row " +
                            std::to_string(after->parsed_row),
                        current.headers[column], "", value});
                    emitted = true;
                    if (result.rows.size() > limits_.max_result_rows)
                        throw std::runtime_error(
                            "Change result safety limit exceeded");
                }
                if (!emitted)
                    result.rows.push_back({
                        "Added", display_key,
                        current.name + " / row " +
                            std::to_string(after->parsed_row),
                        "(record)", "", "Record added"});
                continue;
            }
            if (!after) {
                bool emitted = false;
                for (std::size_t column = 0;
                     column < old.headers.size(); ++column) {
                    const auto normalized = canonical_field_name(
                        old.headers[column]);
                    if (seen_keys.contains(normalized)) continue;
                    const auto value = column < before->row->size()
                        ? trim((*before->row)[column]) : std::string{};
                    if (value.empty()) continue;
                    result.rows.push_back({
                        "Removed", display_key,
                        old.name + " / row " +
                            std::to_string(before->parsed_row),
                        old.headers[column], value, ""});
                    emitted = true;
                    if (result.rows.size() > limits_.max_result_rows)
                        throw std::runtime_error(
                            "Change result safety limit exceeded");
                }
                if (!emitted)
                    result.rows.push_back({
                        "Removed", display_key,
                        old.name + " / row " +
                            std::to_string(before->parsed_row),
                        "(record)", "Record removed", ""});
                continue;
            }
            std::map<std::string, std::string> comparable_fields;
            for (const auto& header : old.headers)
                comparable_fields.try_emplace(
                    canonical_field_name(header), header);
            for (const auto& header : current.headers)
                comparable_fields[canonical_field_name(header)] = header;
            for (const auto& [normalized, header] : comparable_fields) {
                if (seen_keys.contains(normalized)) continue;
                const auto old_column =
                    old.normalized_header_index.find(normalized);
                const auto new_column =
                    current.normalized_header_index.find(normalized);
                const auto old_value = old_column !=
                        old.normalized_header_index.end() &&
                        old_column->second < before->row->size()
                    ? trim((*before->row)[old_column->second])
                    : std::string{};
                const auto new_value = new_column !=
                        current.normalized_header_index.end() &&
                        new_column->second < after->row->size()
                    ? trim((*after->row)[new_column->second])
                    : std::string{};
                if (old_value == new_value) continue;
                std::string change_type = "Modified";
                if (old_column == old.normalized_header_index.end())
                    change_type = "Field Added";
                else if (new_column ==
                         current.normalized_header_index.end())
                    change_type = "Field Removed";
                result.rows.push_back({
                    change_type, display_key,
                    current.name + " / before row " +
                        std::to_string(before->parsed_row) +
                        " -> after row " +
                        std::to_string(after->parsed_row),
                    header, old_value, new_value});
                if (result.rows.size() > limits_.max_result_rows)
                    throw std::runtime_error(
                        "Change result safety limit exceeded");
            }
        }
    }
    if (!compared_any)
        throw std::runtime_error(
            "No previous matching report contains every Change key field");
    result.explanation =
        result.rows.empty()
        ? "No changes were detected against the retained Change baseline."
        : "Observed field-level changes only; unchanged records and fields "
          "are omitted.";
    if (ambiguous_keys_skipped != 0) {
        result.explanation += " " + std::to_string(ambiguous_keys_skipped) +
            " non-unique key(s) with unchanged occurrence counts were "
            "omitted because Point cannot compare them safely.";
    }
    return result;
}

QueryResult Engine::changes_since_auto(
        const Engine& previous,
        const std::string& source_name) const {
    QueryResult combined;
    combined.headers = {
        "Change Type", "Key", "Source / Parsed Row", "Changed Field",
        "Before", "After"};
    const std::vector<std::string> key_priority = {
        "objectguid", "employeeid", "samaccountname", "username",
        "computername", "deviceid", "assetid", "assettag", "groupname",
        "sid", "email", "userprincipalname", "serialnumber"};
    std::map<std::string, const DataSet*> old_by_name;
    for (const auto& dataset : previous.datasets_)
        old_by_name[normalize_name(dataset.name)] = &dataset;
    std::size_t compared_reports = 0;
    std::size_t skipped_reports = 0;
    for (std::size_t dataset_id = 0;
         dataset_id < datasets_.size(); ++dataset_id) {
        const auto& current = datasets_[dataset_id];
        if (!trim(source_name).empty() &&
            !iequals_ascii(current.name, source_name)) continue;
        const auto old_match = old_by_name.find(normalize_name(current.name));
        if (old_match == old_by_name.end()) {
            ++skipped_reports;
            continue;
        }
        const auto& old = *old_match->second;
        std::string selected_key;
        for (const auto& candidate : key_priority) {
            const auto current_column =
                current.normalized_header_index.find(candidate);
            const auto old_column =
                old.normalized_header_index.find(candidate);
            if (current_column == current.normalized_header_index.end() ||
                old_column == old.normalized_header_index.end()) continue;
            if (!indexed_unique_column(dataset_id, current_column->second))
                continue;
            std::set<std::string> old_values;
            bool old_unique = true;
            for (const auto& row : old.rows) {
                const auto value = old_column->second < row.size()
                    ? normalized_field_value(candidate,
                        row[old_column->second]) : std::string{};
                if (value.empty()) continue;
                if (!old_values.insert(value).second) {
                    old_unique = false;
                    break;
                }
            }
            if (!old_unique || old_values.empty()) continue;
            selected_key = current.headers[current_column->second];
            break;
        }
        if (selected_key.empty()) {
            ++skipped_reports;
            continue;
        }
        const auto report_changes = changes_since(
            previous, {selected_key}, current.name);
        combined.rows.insert(
            combined.rows.end(), report_changes.rows.begin(),
            report_changes.rows.end());
        combined.sources.insert(
            combined.sources.end(), report_changes.sources.begin(),
            report_changes.sources.end());
        ++compared_reports;
        if (combined.rows.size() > limits_.max_result_rows)
            throw std::runtime_error(
                "Automatic Change result safety limit exceeded");
    }
    if (compared_reports == 0)
        throw std::runtime_error(
            "No matching baseline report has a safe unique identity key. "
            "Enter one to three key headings manually or refresh matching reports.");
    std::sort(combined.rows.begin(), combined.rows.end(),
        [](const auto& left, const auto& right) {
            if (left.size() < 4 || right.size() < 4) return left.size() < right.size();
            return std::tie(left[2], left[1], left[3], left[0]) <
                   std::tie(right[2], right[1], right[3], right[0]);
        });
    combined.explanation = combined.rows.empty()
        ? "No changes were detected across automatically keyed reports."
        : "All observed field-level changes across automatically keyed reports; unchanged data is omitted.";
    if (skipped_reports != 0)
        combined.explanation += " " + std::to_string(skipped_reports) +
            " report(s) without a matching baseline or safe unique key were skipped.";
    return combined;
}

QueryResult Engine::exact_rows(
        const std::vector<QueryCondition>& conditions,
        const std::vector<std::string>& output_fields,
        const std::string& source_name) const {
    if (conditions.empty() || output_fields.empty() ||
        trim(source_name).empty())
        throw std::runtime_error(
            "Drill-down requires conditions, outputs, and one source");
    const DataSet* selected = nullptr;
    for (const auto& dataset : datasets_) {
        if (iequals_ascii(dataset.name, source_name)) {
            selected = &dataset;
            break;
        }
    }
    if (!selected)
        throw std::runtime_error(
            "The chart source is no longer available");
    std::vector<std::pair<std::size_t, std::string>> resolved_conditions;
    for (const auto& condition : conditions) {
        const auto found = selected->normalized_header_index.find(
            canonical_field_name(condition.field));
        if (found == selected->normalized_header_index.end())
            throw std::runtime_error(
                "A drill-down condition is not in the chart source");
        resolved_conditions.push_back(
            {found->second, trim(condition.value)});
    }
    std::vector<std::size_t> resolved_outputs;
    for (const auto& field : output_fields) {
        const auto found = selected->normalized_header_index.find(
            canonical_field_name(field));
        if (found == selected->normalized_header_index.end())
            throw std::runtime_error(
                "A drill-down output is not in the chart source");
        resolved_outputs.push_back(found->second);
    }
    QueryResult result;
    result.headers = output_fields;
    for (const auto& row : selected->rows) {
        bool matches = true;
        for (const auto& [column, expected] : resolved_conditions) {
            const auto actual =
                column < row.size() ? trim(row[column])
                                    : std::string{};
            if (!iequals_ascii(actual, expected)) {
                matches = false;
                break;
            }
        }
        if (!matches) continue;
        std::vector<std::string> output;
        for (const auto column : resolved_outputs)
            output.push_back(
                column < row.size() ? row[column] : std::string{});
        result.rows.push_back(std::move(output));
        if (result.rows.size() > limits_.max_result_rows)
            throw std::runtime_error(
                "Drill-down result safety limit exceeded");
    }
    result.sources.push_back(selected->name);
    result.explanation =
        "Exact source-bound chart drill-down.";
    return result;
}

void Engine::export_csv(const QueryResult& result,
                        const std::filesystem::path& destination,
                        ExportPolicy policy) const {
    if (result.headers.empty())
        throw std::runtime_error("Cannot export a result without headers");
    for (const auto& row : result.rows) {
        for (const auto& value : row) {
            if (policy.block_payment_card_numbers &&
                looks_like_payment_card_number(trim(value))) {
                throw std::runtime_error(
                    "Export blocked: possible payment card number detected");
            }
        }
    }
    std::ofstream output(destination, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("Unable to create export");
    auto write_record = [&output](const std::vector<std::string>& row) {
        for (std::size_t i = 0; i < row.size(); ++i) {
            if (i) output << ',';
            output << csv_quote(row[i]);
        }
        output << "\r\n";
    };
    write_record(result.headers);
    for (const auto& row : result.rows) {
        auto protected_row = row;
        if (policy.mask_highly_sensitive_fields) {
            const auto width = std::min(
                protected_row.size(), result.headers.size());
            for (std::size_t i = 0; i < width; ++i) {
                if (is_highly_sensitive_field(result.headers[i]))
                    protected_row[i] =
                        mask_sensitive_value(protected_row[i]);
            }
        }
        write_record(protected_row);
    }
    if (!output) throw std::runtime_error("Export write failed");
}

void ensure_directories(const std::filesystem::path& root) {
    for (const char* name : {"Inbox", "Workspace", "Exports", "Logs"}) {
        std::filesystem::create_directories(root / name);
    }
}

void append_audit(const std::filesystem::path& root,
                  const std::string& event,
                  const std::string& detail) {
    const auto path = root / "Logs" / "point-audit.log";
    const auto timestamp = timestamp_utc();
    const auto safe_event = audit_safe(event);
    const auto safe_detail = audit_safe(detail);
    const auto previous = last_audit_hash(path);
    const auto digest = audit_digest(
        previous + "|" + timestamp + "|" + safe_event + "|" + safe_detail);
    std::ofstream log(path,
                      std::ios::binary | std::ios::app);
    if (log) {
        log << timestamp << '\t' << safe_event << '\t' << safe_detail
            << '\t' << previous << '\t' << digest << '\n';
        log.flush();
    }
}

AssistantPlan plan_assistant_request(
    const std::string& request,
    const std::vector<std::string>& available_fields) {
    const auto clean = trim(request);
    if (clean.empty())
        throw std::runtime_error("Type what Point should find");
    const auto normalized = normalize_name(clean);
    auto command_lower = clean;
    std::transform(command_lower.begin(), command_lower.end(), command_lower.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    auto available = [&](const std::string& wanted) {
        for (const auto& field : available_fields)
            if (normalize_name(field) == normalize_name(wanted)) return field;
        return std::string{};
    };
    auto add = [&](AssistantPlan& plan, const std::string& field) {
        const auto found = available(field);
        if (!found.empty() && std::find(plan.fields.begin(), plan.fields.end(), found) == plan.fields.end())
            plan.fields.push_back(found);
    };
    auto identity_after_for = [&]() {
        auto lower = clean;
        std::transform(lower.begin(), lower.end(), lower.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        const auto pos = lower.rfind(" for ");
        if (pos == std::string::npos) return std::string{};
        return trim(clean.substr(pos + 5));
    };

    AssistantPlan plan;
    if (command_lower.find("count by") != std::string::npos) {
        plan.mode = AssistantMode::Count;
        const auto pos = command_lower.find("count by");
        const auto wanted = trim(command_lower.substr(pos + 8));
        for (const auto& field : available_fields)
            if (normalize_name(field) == wanted) plan.fields.push_back(field);
        if (plan.fields.empty()) throw std::runtime_error("Point could not identify the field to count");
        plan.summary = "Count records by " + plan.fields.front();
        return plan;
    }

    const bool groups = command_lower.find("group") != std::string::npos;
    const bool computers = command_lower.find("computer") != std::string::npos;
    const bool compare = command_lower.find("compare") != std::string::npos;
    auto identities = identity_after_for();
    if (compare) {
        auto lower_identities = identities;
        std::transform(lower_identities.begin(), lower_identities.end(), lower_identities.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        const auto marker = lower_identities.find(" and ");
        if (marker == std::string::npos)
            throw std::runtime_error("Compare needs two values, for example: compare groups for speela and jsmith");
        // The normalized and original strings have equal length for ordinary command text.
        plan.inputs = {trim(identities.substr(0, marker)), trim(identities.substr(marker + 5))};
        plan.mode = AssistantMode::Compare;
        add(plan, "SAM Account Name");
        if (groups) add(plan, "Group Name");
        if (plan.fields.size() < 2) throw std::runtime_error("The requested comparison fields are not imported");
        plan.summary = "Compare " + plan.inputs[0] + " and " + plan.inputs[1] + " by " + plan.fields.back();
        return plan;
    }
    if (identities.empty())
        throw std::runtime_error("Include a value after 'for', for example: groups for speela");
    plan.inputs.push_back(identities);
    add(plan, "SAM Account Name");
    if (groups) {
        add(plan, "Display Name");
        add(plan, "Group Name");
    } else if (computers) {
        add(plan, "Computer Name");
        add(plan, "Operating System");
        add(plan, "Computer Status");
        add(plan, "BitLocker Status");
    } else {
        for (const auto& field : available_fields)
            if (normalized.find(normalize_name(field)) != std::string::npos) add(plan, field);
    }
    if (plan.fields.size() < 2)
        throw std::runtime_error("Point could not identify enough imported fields for that request");
    plan.summary = "Find " + std::to_string(plan.fields.size() - 1) + " field(s) for " + identities;
    return plan;
}

RiskAssessment assess_offline_risk(
    const std::string& entity, const QueryResult& evidence) {
    RiskAssessment assessment;
    assessment.entity = trim(entity);
    if (assessment.entity.empty()) throw std::runtime_error("Enter a username, computer, or group");
    if (evidence.rows.empty()) throw std::runtime_error("NOT FOUND in the imported evidence");
    auto column = [&](const std::string& name) -> std::optional<std::size_t> {
        for (std::size_t i = 0; i < evidence.headers.size(); ++i)
            if (normalize_name(evidence.headers[i]) == normalize_name(name)) return i;
        return std::nullopt;
    };
    auto values = [&](const std::string& name) {
        std::set<std::string> unique;
        const auto index = column(name);
        if (!index) return unique;
        for (const auto& row : evidence.rows)
            if (*index < row.size() && !trim(row[*index]).empty()) unique.insert(trim(row[*index]));
        return unique;
    };
    auto add = [&](std::string severity, double score, std::string title,
                   std::string facts, std::string reason, std::string solution,
                   std::vector<std::string> mappings, bool official = false) {
        assessment.findings.push_back({std::move(severity), score, official,
            std::move(title), std::move(facts), std::move(reason),
            std::move(solution), std::move(mappings)});
        assessment.maximum_score = std::max(assessment.maximum_score, score);
        assessment.has_authoritative_cvss |= official;
    };

    const auto operating_systems = values("Operating System");
    for (const auto& os : operating_systems) {
        const auto n = normalize_name(os);
        if (n.find("windows7") != std::string::npos || n.find("windows8") != std::string::npos ||
            n.find("server2008") != std::string::npos || n.find("server2012") != std::string::npos) {
            add("High", 8.1, "Legacy operating system", "Operating System: " + os,
                "Legacy platforms may no longer receive complete security fixes and increase exploitability.",
                "Validate business ownership, isolate the asset, patch all supported components, and migrate to a supported operating system.",
                {"NIST CSF 2.0 PR.PS-02", "PCI DSS 4.0.1 6.3.3", "CIS Controls v8 7.4", "ISO 27001:2022 A.8.8"});
        }
    }
    const auto encryption = values("BitLocker Status");
    for (const auto& state : encryption) {
        const auto n = normalize_name(state);
        if (n.find("enabled") == std::string::npos && n.find("encrypted") == std::string::npos) {
            add("High", 7.4, "Endpoint encryption not confirmed", "BitLocker Status: " + state,
                "Unencrypted endpoint storage can expose regulated or confidential data after loss or theft.",
                "Confirm the device supports BitLocker, escrow the recovery key, enable encryption, and verify policy compliance.",
                {"NIST CSF 2.0 PR.DS-01", "PCI DSS 4.0.1 3.5.1", "CIS Controls v8 3.6", "ISO 27001:2022 A.8.24"});
        }
    }
    const auto groups = values("Group Name");
    for (const auto& group : groups) {
        const auto n = normalize_name(group);
        if (n.find("domainadmins") != std::string::npos || n.find("enterpriseadmins") != std::string::npos ||
            n.find("administrators") != std::string::npos) {
            add("High", 8.8, "Privileged group exposure", "Group Name: " + group,
                "Membership can provide broad administrative capability and magnify credential compromise impact.",
                "Verify ticket and owner approval, enforce least privilege and MFA, use time-bound access, and review membership regularly.",
                {"NIST CSF 2.0 PR.AA-05", "PCI DSS 4.0.1 7.2.5", "CIS Controls v8 5.4", "ISO 27001:2022 A.8.2"});
        }
    }
    const auto computer_status = values("Computer Status");
    if (!computer_status.empty()) {
        for (const auto& state : computer_status) {
            const auto n = normalize_name(state);
            if (n.find("inactive") != std::string::npos || n.find("stale") != std::string::npos || n.find("disabled") != std::string::npos) {
                add("Medium", 6.5, "Inactive or stale computer record", "Computer Status: " + state,
                    "Unmanaged or stale assets can retain accounts, software, or network access outside normal control coverage.",
                    "Confirm last activity and ownership; isolate, remediate, or formally decommission the asset and remove obsolete directory records.",
                    {"NIST CSF 2.0 ID.AM-08", "PCI DSS 4.0.1 2.2.1", "CIS Controls v8 1.1", "ISO 27001:2022 A.5.9"});
            }
        }
    }
    const auto account_status = values("Account Status");
    for (const auto& state : account_status) {
        const auto n = normalize_name(state);
        if (n.find("locked") != std::string::npos) {
            add("Medium", 5.3, "Account is locked", "Account Status: " + state,
                "A lockout may indicate repeated authentication failures, stale credentials, or malicious attempts.",
                "Review authentication logs and source devices before unlocking; reset credentials and revoke sessions if compromise is suspected.",
                {"NIST CSF 2.0 DE.CM-03", "PCI DSS 4.0.1 10.4.1", "CIS Controls v8 8.5", "ISO 27001:2022 A.8.16"});
        }
    }
    for (const auto& field : {std::string("CVSS Score"), std::string("Base Score")}) {
        for (const auto& value : values(field)) {
            try {
                const double score = std::clamp(std::stod(value), 0.0, 10.0);
                add(score >= 9 ? "Critical" : score >= 7 ? "High" : score >= 4 ? "Medium" : "Low",
                    score, "Imported vulnerability score", field + ": " + value,
                    "The score was supplied by an imported vulnerability source.",
                    "Use the associated vulnerability identifier and vendor guidance to prioritize remediation and verify closure.",
                    {"NIST CSF 2.0 ID.RA-01", "PCI DSS 4.0.1 6.3.1", "CIS Controls v8 7.2", "ISO 27001:2022 A.8.8"}, true);
            } catch (...) {}
        }
    }
    if (assessment.findings.empty()) {
        add("Information", 0.0, "No offline rule triggered",
            "Imported values reviewed: " + std::to_string(evidence.rows.size()) + " matching row(s)",
            "The available imported columns did not trigger a configured Point risk rule. This is not proof of compliance or absence of risk.",
            "Import current vulnerability, patch, encryption, status, privilege, and authentication reports, then assess again.",
            {"NIST CSF 2.0 ID.RA-01", "PCI DSS 4.0.1 12.3.1"});
    }
    assessment.rating = assessment.maximum_score >= 9 ? "Critical" :
        assessment.maximum_score >= 7 ? "High" : assessment.maximum_score >= 4 ? "Medium" :
        assessment.maximum_score > 0 ? "Low" : "Informational";
    assessment.limitations.push_back("Assessment uses only currently imported evidence and deterministic offline rules.");
    if (!assessment.has_authoritative_cvss)
        assessment.limitations.push_back("Scores are internal CVSS-style priority estimates, not official CVSS calculations; import CVSS Score or Base Score for authoritative values.");
    assessment.limitations.push_back("Framework mappings are guidance and do not by themselves establish compliance.");
    return assessment;
}

}  // namespace point
