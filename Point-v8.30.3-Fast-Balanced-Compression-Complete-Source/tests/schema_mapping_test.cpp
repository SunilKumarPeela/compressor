#include "point_core.h"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>

int main() {
    const auto root = std::filesystem::temp_directory_path() /
        "point-schema-mapping-test";
    std::filesystem::create_directories(root);
    const auto users = root / "Users.csv";
    const auto devices = root / "Devices.csv";

    point::QueryResult text_tools;
    text_tools.headers = {"Username", "Status"};
    text_tools.rows = {
        {"global/speela", "Active"},
        {"global/jsmith", "Disabled"},
        {"local/adoe", "Active"},
        {"", "Active"}
    };
    const auto active_filter = point::filter_query_result(
        text_tools, 1, point::RowFilterOperator::Equals, "active");
    assert(active_filter.rows.size() == 3);
    const auto global_filter = point::filter_query_result(
        text_tools, 0, point::RowFilterOperator::StartsWith, "GLOBAL/");
    assert(global_filter.rows.size() == 2);
    const auto blank_filter = point::filter_query_result(
        text_tools, 0, point::RowFilterOperator::IsBlank);
    assert(blank_filter.rows.size() == 1);
    const auto split_usernames = point::split_query_result_column(
        text_tools, 0, "/");
    assert(split_usernames.headers.size() == 4);
    assert(split_usernames.headers[2] == "Username Part 1");
    assert(split_usernames.headers[3] == "Username Part 2");
    assert(split_usernames.rows[0][0] == "global/speela");
    assert(split_usernames.rows[0][2] == "global");
    assert(split_usernames.rows[0][3] == "speela");
    const auto remove_domain = point::remove_text_pattern(
        "global/speela", "global/", point::TextMatchPosition::Prefix);
    assert(remove_domain && *remove_domain == "speela");
    const auto remove_domain_case = point::remove_text_pattern(
        "GLOBAL/jsmith", "global/", point::TextMatchPosition::Prefix);
    assert(remove_domain_case && *remove_domain_case == "jsmith");
    const auto wrong_position = point::remove_text_pattern(
        "local/global/user", "global/", point::TextMatchPosition::Prefix);
    assert(!wrong_position);
    const auto remove_suffix = point::remove_text_pattern(
        "sunil@company.com", "@company.com", point::TextMatchPosition::Suffix);
    assert(remove_suffix && *remove_suffix == "sunil");
    const auto skip_left = point::keep_text_side(
        "different-domain/sunil", "/", point::TextSide::Right);
    assert(skip_left && *skip_left == "sunil");
    const auto skip_right = point::keep_text_side(
        "Engineering, Grace", ",", point::TextSide::Left);
    assert(skip_right && *skip_right == "Engineering");
    assert(!point::keep_text_side(
        "no delimiter", "/", point::TextSide::Right));
    {
        std::ofstream out(users);
        out << "Employee ID,Username,Email,Display Name,Manager Employee ID\n"
               "E1001,speela,sunil@example.com,\"Peela, Sunil Kumar\",\n"
               "E1002,jsmith,john@example.com,Smith John,E1001\n";
    }
    {
        std::ofstream out(devices);
        out << "Associate Number,Computer Name\n"
               "E1001,PC-001\nE1002,PC-002\n";
    }

    point::Engine unmapped;
    unmapped.load_files({users, devices});
    assert(unmapped.relationships().empty());

    point::Engine mapped;
    mapped.set_field_synonyms({
        {"Employee ID", {"EID", "Associate Number", "Worker ID"}}
    });
    mapped.load_files({users, devices});
    assert(mapped.relationships().size() == 1);
    point::QueryRequest request;
    request.lookup_field = "Employee ID";
    request.lookup_value = "E1001";
    request.output_fields = {"Display Name", "Computer Name"};
    const auto result = mapped.query(request);
    assert(result.rows.size() == 1);
    assert(result.rows[0][0] == "Peela, Sunil Kumar");
    assert(result.rows[0][1] == "PC-001");

    // Worksheets with identical headings must remain independent datasets;
    // loading one sheet must never shadow the rows from another sheet.
    const auto sheet_one = root / "Book__Sheet1.csv";
    const auto sheet_two = root / "Book__Sheet2.csv";
    const auto sheet_three = root / "Book__Sheet3.csv";
    {
        std::ofstream out(sheet_one);
        out << "Employee ID,Username,Status\nE2001,alpha,Active\n";
    }
    {
        std::ofstream out(sheet_two);
        out << "Employee ID,Username,Status\nE2002,beta,Disabled\n";
    }
    {
        std::ofstream out(sheet_three);
        out << "Employee ID,Username,Status\nE2003,gamma,Locked\n";
    }
    point::Engine same_schema_sheets;
    same_schema_sheets.load_files({sheet_one, sheet_two, sheet_three});
    assert(same_schema_sheets.datasets().size() == 3);
    for (const auto& expected : {
             std::pair{"E2001", "alpha"},
             std::pair{"E2002", "beta"},
             std::pair{"E2003", "gamma"}}) {
        point::QueryRequest sheet_request;
        sheet_request.lookup_field = "Employee ID";
        sheet_request.lookup_value = expected.first;
        sheet_request.output_fields = {"Username", "Status"};
        const auto sheet_result = same_schema_sheets.query(sheet_request);
        assert(sheet_result.rows.size() == 1);
        assert(sheet_result.rows[0][0] == expected.second);
    }

    // A unique match in one worksheet must not prune repeated matches from a
    // second worksheet with the same headings.
    const auto unique_matches = root / "MatchBook__Unique.csv";
    const auto repeated_matches = root / "MatchBook__Repeated.csv";
    {
        std::ofstream out(unique_matches);
        out << "Employee ID,Username,Status\n"
               "E3001,one,Active\n";
    }
    {
        std::ofstream out(repeated_matches);
        out << "Employee ID,Username,Status\n"
               "E3001,two,Disabled\n"
               "E3001,three,Locked\n";
    }
    point::Engine all_sheet_matches;
    all_sheet_matches.load_files({unique_matches, repeated_matches});
    point::QueryRequest all_matches_request;
    all_matches_request.lookup_field = "Employee ID";
    all_matches_request.lookup_value = "E3001";
    all_matches_request.output_fields = {"Username", "Status"};
    const auto all_matches = all_sheet_matches.query(all_matches_request);
    assert(all_matches.rows.size() == 3);
    const auto universal_matches = all_sheet_matches.universal_lookup(
        {"Employee ID", "Username", "Status"}, "E3001");
    assert(universal_matches.rows.size() == 3);

    const auto stale_profile = root / "StaleCompleteProfile.csv";
    const auto current_email = root / "CurrentPartialEmail.csv";
    const auto repeated_current_email = root / "RepeatedCurrentEmail.csv";
    {
        std::ofstream out(stale_profile);
        out << "Username,Email,Department\n"
               "speela,sunil@company.com,Security\n";
    }
    {
        std::ofstream out(current_email);
        out << "SAM Account Name,Email\n"
               "speela,speela@jbssa.com\n";
    }
    {
        std::ofstream out(repeated_current_email);
        out << "SAM Account Name,Email\n"
               "speela,speela@jbssa.com\n";
    }
    point::Engine consolidated_identity;
    consolidated_identity.load_files(
        {stale_profile, current_email, repeated_current_email});
    const auto consolidated = consolidated_identity.universal_lookup(
        {"Email", "SAM Account Name", "Username", "Department"},
        "speela");
    assert(consolidated.rows.size() == 2);
    std::set<std::string> consolidated_emails;
    for (const auto& row : consolidated.rows) {
        assert(row.size() == 4);
        assert(row[1] == "speela");
        assert(row[2] == "speela");
        assert(row[3] == "Security");
        consolidated_emails.insert(row[0]);
    }
    assert(consolidated_emails.contains("sunil@company.com"));
    assert(consolidated_emails.contains("speela@jbssa.com"));

    // Group exports may store many usernames in one membership cell. Each
    // delimited member must be searchable as an exact token, regardless of
    // whitespace, without allowing substring matches.
    const auto packed_members = root / "PackedGroupMembers.csv";
    {
        std::ofstream out(packed_members);
        out << "Group Name,Members\n"
               "Security-Readers,\"name1, name2, speela, name3\"\n"
               "VPN-Users,\"jsmith; speela; adoe\"\n"
               "Finance,other-speela\n";
    }
    point::Engine membership_engine;
    membership_engine.load_files({packed_members});
    const auto memberships = membership_engine.universal_lookup(
        {"Group Name"}, "speela");
    assert(memberships.rows.size() == 2);
    std::set<std::string> membership_names;
    for (const auto& row : memberships.rows)
        membership_names.insert(row[0]);
    assert(membership_names.contains("Security-Readers"));
    assert(membership_names.contains("VPN-Users"));
    const auto partial_member = membership_engine.universal_lookup(
        {"Group Name"}, "peela");
    assert(partial_member.rows.empty());

    const auto display_name_members = root / "DisplayNameMembers.csv";
    {
        std::ofstream out(display_name_members);
        out << "Group Name,Members\n"
               "Admins,\"Sunil, Peela; John, Smith; Grace, Doe\"\n";
    }
    point::Engine display_membership_engine;
    display_membership_engine.load_files({display_name_members});
    const auto display_memberships =
        display_membership_engine.universal_lookup(
            {"Group Name"}, "Sunil Peela");
    assert(display_memberships.rows.size() == 1);
    assert(display_memberships.rows[0][0] == "Admins");
    const auto separated_first_name =
        display_membership_engine.universal_lookup(
            {"Group Name"}, "Sunil");
    assert(separated_first_name.rows.empty());

    // ADManager user and group exports use different headings for the two
    // sides of membership. Member Of must connect to Group Name, and a
    // semicolon-delimited Members' Names cell must connect to Display Name.
    const auto ad_users = root / "ADUsers.csv";
    const auto ad_groups = root / "ADGroups.csv";
    {
        std::ofstream out(ad_users);
        out << "SAM Account Name,Display Name,Member Of\n"
               "speela,\"Sunil, Peela\",\"Security-Readers; VPN-Users\"\n"
               "jsmith,\"Smith, John\",\"Common-Access; John-Only\"\n";
    }
    {
        std::ofstream out(ad_groups);
        out << "Group Name,Members' Names,Description\n"
               "Security-Readers,\"Sunil, Peela; John, Smith\",Read access\n"
               "VPN-Users,\"Sunil, Peela; Grace, Doe\",VPN access\n";
    }
    point::Engine ad_membership_engine;
    ad_membership_engine.load_files({ad_users, ad_groups});
    const auto linked_groups = ad_membership_engine.universal_lookup(
        {"Group Name", "Description"}, "speela");
    assert(linked_groups.rows.size() == 2);
    std::set<std::string> linked_group_names;
    for (const auto& row : linked_groups.rows)
        linked_group_names.insert(row[0]);
    assert(linked_group_names.contains("Security-Readers"));
    assert(linked_group_names.contains("VPN-Users"));

    // Some group exports call the same semicolon-delimited display-name list
    // simply "Members". It must link to the employee Display Name column,
    // while each token remains an exact complete-name match.
    const auto plain_member_groups = root / "PlainMemberGroups.csv";
    {
        std::ofstream out(plain_member_groups);
        out << "Group Name,Display Name,Members,Description\n"
               "Finance-Readers,Finance Readers,"
               "\"Peela, Sunil; Smith, John\",Finance\n"
               "Device-Admins,Device Administrators,"
               "\"Doe, Grace; Peela, Sunil\",Devices\n";
    }
    point::Engine plain_member_relationship;
    plain_member_relationship.load_files({ad_users, plain_member_groups});
    const auto plain_member_results =
        plain_member_relationship.universal_lookup(
            {"Group Name", "Description"}, "speela");
    assert(plain_member_results.rows.size() == 2);
    std::set<std::string> plain_member_group_names;
    for (const auto& row : plain_member_results.rows)
        plain_member_group_names.insert(row[0]);
    assert(plain_member_group_names.contains("Finance-Readers"));
    assert(plain_member_group_names.contains("Device-Admins"));

    // Group membership must still work when automatic relationship overlap is
    // intentionally too low. Exact Display Name -> Members enrichment should
    // return the matching group without a Relationship Manager rule.
    const auto sparse_member_groups = root / "SparseMemberGroups.csv";
    {
        std::ofstream out(sparse_member_groups);
        out << "Group Name,Display Name,Members\n"
               "Administrators,Administrators,"
               "\"Peela, Sunil; James, wattspon; ram, potineni\"\n";
        for (int index = 0; index < 20; ++index)
            out << "Other-" << index << ",Other " << index
                << ",Unmatched Person " << index << "\n";
    }
    point::Engine deterministic_group_membership;
    deterministic_group_membership.load_files(
        {ad_users, sparse_member_groups});
    const auto deterministic_groups =
        deterministic_group_membership.universal_lookup(
            {"SAM Account Name", "Display Name", "Group Name"},
            "speela");
    assert(deterministic_groups.rows.size() == 1);
    assert(deterministic_groups.rows[0][2] == "Administrators");
    const auto hidden_display_bridge =
        deterministic_group_membership.universal_lookup(
            {"SAM Account Name", "Group Name"}, "speela");
    assert(hidden_display_bridge.rows.size() == 1);
    assert(hidden_display_bridge.rows[0][0] == "speela");
    assert(hidden_display_bridge.rows[0][1] == "Administrators");

    const auto comparison_groups = root / "ComparisonGroups.csv";
    {
        std::ofstream out(comparison_groups);
        out << "Group Name,Members\n"
               "Common-Access,\"Peela, Sunil; Smith, John\"\n"
               "Sunil-Only,\"Peela, Sunil\"\n"
               "John-Only,\"Smith, John\"\n";
    }
    point::Engine group_compare_engine;
    group_compare_engine.load_files({ad_users, comparison_groups});
    const auto direct_sam_groups = group_compare_engine.universal_lookup(
        {"SAM Account Name", "Group Name"}, "speela");
    std::set<std::string> direct_sam_group_names;
    for (const auto& row : direct_sam_groups.rows) {
        assert(row.size() == 2);
        assert(row[0] == "speela");
        direct_sam_group_names.insert(row[1]);
    }
    assert(direct_sam_group_names ==
        std::set<std::string>({"Common-Access", "Sunil-Only"}));
    const auto group_comparison = group_compare_engine.compare_profiles(
        "SAM Account Name", "speela", "jsmith", {"Group Name"});
    assert(group_comparison.headers.size() == 4);
    assert(group_comparison.rows.size() == 3);
    assert(group_comparison.rows[0][0] == "Common-Access");
    assert(group_comparison.rows[0][1] == "Common");
    std::map<std::string, std::vector<std::string>> compared_groups;
    for (const auto& row : group_comparison.rows)
        compared_groups[row[0]] = row;
    assert(compared_groups["Sunil-Only"][1] == "Not Common");
    assert(compared_groups["Sunil-Only"][2] == "speela");
    assert(compared_groups["Sunil-Only"][3] == "jsmith");
    assert(compared_groups["John-Only"][2] == "jsmith");
    assert(compared_groups["John-Only"][3] == "speela");

    const auto matrix_users = root / "MatrixUsers.csv";
    const auto matrix_groups = root / "MatrixGroups.csv";
    {
        std::ofstream out(matrix_users);
        out << "SAM Account Name,Display Name\n"
               "user1,User One\nuser2,User Two\nuser3,User Three\n";
    }
    {
        std::ofstream out(matrix_groups);
        out << "Group Name,Members\n"
               "Administrators,\"User One; User Two; User Three\"\n"
               "cyberarksafe,\"User One; User Two\"\n"
               "verkada1,User One\n"
               "azuremfa,User Two\n"
               "users,\"User One; User Two; User Three\"\n"
               "user3-only,User Three\n";
    }
    point::Engine matrix_engine;
    matrix_engine.load_files({matrix_users, matrix_groups});
    const auto group_matrix = matrix_engine.compare_group_matrix(
        "SAM Account Name", {"user1", "user2", "user3"});
    assert(group_matrix.headers ==
        std::vector<std::string>({"user1", "user2", "user3"}));
    std::map<std::string, std::vector<std::string>> matrix_rows;
    for (const auto& row : group_matrix.rows) {
        const auto first_value = std::find_if(
            row.begin(), row.end(),
            [](const auto& value) { return !value.empty(); });
        assert(first_value != row.end());
        matrix_rows[*first_value] = row;
    }
    assert(matrix_rows["Administrators"] ==
        std::vector<std::string>({"Administrators", "Administrators", "Administrators"}));
    assert(matrix_rows["cyberarksafe"] ==
        std::vector<std::string>({"cyberarksafe", "cyberarksafe", ""}));
    assert(matrix_rows["verkada1"] ==
        std::vector<std::string>({"verkada1", "", ""}));
    assert(matrix_rows["azuremfa"] ==
        std::vector<std::string>({"", "azuremfa", ""}));
    assert(matrix_rows["user3-only"] ==
        std::vector<std::string>({"", "", "user3-only"}));

    const auto custom_people = root / "CustomPeople.csv";
    const auto custom_access = root / "CustomAccess.csv";
    {
        std::ofstream out(custom_people);
        out << "Login ID,Assigned Access\n"
               "speela,\"Privileged; RemoteAccess\"\n";
    }
    {
        std::ofstream out(custom_access);
        out << "Security Role,Risk\n"
               "Privileged,High\nRemoteAccess,Medium\n";
    }
    point::Engine configured_relationship_engine;
    configured_relationship_engine.set_user_relationships({{
        "Assigned Access", "Security Role",
        point::RelationshipMatchMode::LeftListContainsRight,
        ";", 0.20, true
    }});
    configured_relationship_engine.load_files(
        {custom_people, custom_access});
    const auto configured_roles =
        configured_relationship_engine.universal_lookup(
            {"Security Role", "Risk"}, "speela");
    assert(configured_roles.rows.size() == 2);

    // A user may already have made two differently named identity columns
    // synonymous. Quick linking them as equivalent must reinforce the
    // cross-file relationship instead of rejecting the rule as redundant.
    const auto logged_users = root / "LoggedUsers.csv";
    const auto directory_users = root / "DirectoryUsers.csv";
    {
        std::ofstream out(logged_users);
        out << "Computer Name,Logged On Users,Location,Owner Email\n"
               "PC-77,speela,Greeley,owner@example.com\n";
    }
    {
        std::ofstream out(directory_users);
        out << "SAM Account Name,Email Address\nspeela,speela@example.com\n";
    }
    point::Engine synonymous_relationship_engine;
    synonymous_relationship_engine.set_field_synonyms({
        {"SAM Account Name", {"Logged On Users"}}
    });
    synonymous_relationship_engine.set_user_relationships({{
        "Logged On Users", "SAM Account Name",
        point::RelationshipMatchMode::Equivalent, ";", 0.05, true
    }});
    synonymous_relationship_engine.load_files(
        {logged_users, directory_users});
    const auto synonymous_computer =
        synonymous_relationship_engine.universal_lookup(
            {"SAM Account Name", "Computer Name", "Location", "Owner Email"},
            "speela");
    assert(synonymous_computer.rows.size() == 1);
    assert(synonymous_computer.rows[0][1] == "PC-77");
    assert(synonymous_computer.rows[0][2] == "Greeley");
    assert(synonymous_computer.rows[0][3] == "owner@example.com");

    // Requested device details may live one validated relationship beyond
    // the logged-user report. The intermediate workbook must be traversed
    // even when Computer Name itself is not selected for display.
    const auto computer_inventory = root / "ComputerInventory.csv";
    {
        std::ofstream out(computer_inventory);
        out << "Computer Name,Operating System,Computer Status,"
               "BitLocker Status\n"
               "PC-77,Windows 11 Pro,Enabled,Encrypted\n";
    }
    point::Engine device_detail_engine;
    device_detail_engine.set_field_synonyms({
        {"SAM Account Name", {"Logged On Users"}}
    });
    device_detail_engine.set_user_relationships({{
        "Logged On Users", "SAM Account Name",
        point::RelationshipMatchMode::Equivalent, ";", 0.05, true
    }});
    device_detail_engine.load_files(
        {logged_users, directory_users, computer_inventory});
    const auto device_details = device_detail_engine.universal_lookup(
        {"SAM Account Name", "Operating System", "Computer Status",
         "BitLocker Status"},
        "speela");
    assert(device_details.rows.size() == 1);
    assert(device_details.rows[0][0] == "speela");
    assert(device_details.rows[0][1] == "Windows 11 Pro");
    assert(device_details.rows[0][2] == "Enabled");
    assert(device_details.rows[0][3] == "Encrypted");

    // Even when duplicate Computer Name rows prevent an automatic inventory
    // relationship, a computer already resolved through Logged On Users can
    // safely enrich a missing field when all exact inventory matches agree.
    const auto duplicate_logged = root / "DuplicateLoggedUsers.csv";
    const auto duplicate_inventory = root / "DuplicateInventory.csv";
    {
        std::ofstream out(duplicate_logged);
        out << "Computer Name,Logged On Users\n"
               "PC-88,speela\nPC-88,speela\n";
    }
    {
        std::ofstream out(duplicate_inventory);
        out << "Computer Name,Operating System\n"
               "PC-88,Windows 11 Enterprise\n"
               "PC-88,Windows 11 Enterprise\n";
    }
    point::Engine exact_device_enrichment;
    exact_device_enrichment.set_field_synonyms({
        {"SAM Account Name", {"Logged On Users"}}
    });
    exact_device_enrichment.set_user_relationships({{
        "Logged On Users", "SAM Account Name",
        point::RelationshipMatchMode::Equivalent, ";", 0.05, true
    }});
    exact_device_enrichment.load_files(
        {duplicate_logged, directory_users, duplicate_inventory});
    const auto enriched_device = exact_device_enrichment.universal_lookup(
        {"SAM Account Name", "Computer Name", "Operating System"},
        "speela");
    assert(enriched_device.rows.size() == 1);
    assert(enriched_device.rows[0][1] == "PC-88");
    assert(enriched_device.rows[0][2] == "Windows 11 Enterprise");

    point::Engine incremental;
    incremental.set_field_synonyms({
        {"Employee ID", {"EID", "Associate Number", "Worker ID"}}
    });
    std::size_t reused_files = 0;
    incremental.load_files_incremental(
        {users, devices}, &mapped,
        [&](std::size_t, std::size_t,
            const std::filesystem::path&, bool reused) {
            if (reused) ++reused_files;
        });
    assert(reused_files == 2);
    assert(incremental.relationships().size() == 1);
    const auto incremental_result = incremental.query(request);
    assert(incremental_result.rows == result.rows);

    const auto username = mapped.resolve_identity_from_name(
        "Username", "Sunil Kumar Peela");
    assert(username.status == point::IdentityResolutionStatus::Unique);
    assert(username.value == "speela");
    const auto employee = mapped.resolve_identity_from_name(
        "Employee ID", "Peela, Sunil Kumar");
    assert(employee.status == point::IdentityResolutionStatus::Unique);
    assert(employee.value == "E1001");
    const auto email = mapped.resolve_identity_from_name(
        "Email", "Sunil Kumar Peela");
    assert(email.status == point::IdentityResolutionStatus::Unique);
    assert(email.value == "sunil@example.com");

    const auto computer_to_username = mapped.universal_lookup(
        {"Username"}, "PC-001");
    assert(computer_to_username.rows.size() == 1);
    assert(computer_to_username.rows[0][0] == "speela");
    const auto email_to_computer = mapped.universal_lookup(
        {"Computer Name"}, "sunil@example.com");
    assert(email_to_computer.rows.size() == 1);
    assert(email_to_computer.rows[0][0] == "PC-001");
    const auto email_to_employee = mapped.universal_lookup(
        {"Employee ID"}, "john@example.com");
    assert(email_to_employee.rows.size() == 1);
    assert(email_to_employee.rows[0][0] == "E1002");
    const auto computer_to_name = mapped.universal_lookup(
        {"Display Name"}, "PC-001");
    assert(computer_to_name.rows.size() == 1);
    assert(computer_to_name.rows[0][0] == "Peela, Sunil Kumar");
    const auto reordered_name = mapped.universal_lookup(
        {"Display Name", "Username", "Computer Name"},
        "Sunil Kumar Peela");
    assert(reordered_name.rows.size() == 1);
    assert(reordered_name.rows[0][0] == "Peela, Sunil Kumar");
    assert(reordered_name.rows[0][1] == "speela");
    assert(reordered_name.rows[0][2] == "PC-001");

    // The exact Username seed must remain the identity authority even when a
    // related group report contains a different Employee ID. Relationship
    // traversal may fill Department, but it must never replace the seed EID.
    const auto seed_identity = root / "SeedIdentity.csv";
    const auto related_group = root / "RelatedGroup.csv";
    {
        std::ofstream out(seed_identity);
        out << "Username,Employee ID,Group Name\n"
               "speela,E1001,Security Team\n";
    }
    {
        std::ofstream out(related_group);
        out << "Group Name,Employee ID,Department\n"
               "Security Team,E9999,Cybersecurity\n";
    }
    point::Engine seed_authority_engine;
    seed_authority_engine.load_files({seed_identity, related_group});
    point::QueryRequest seed_authority_request;
    seed_authority_request.conditions.push_back({"Username", "speela"});
    seed_authority_request.output_fields = {
        "Employee ID", "Department"};
    const auto seed_authority_result =
        seed_authority_engine.query(seed_authority_request);
    assert(seed_authority_result.rows.size() == 1);
    assert(seed_authority_result.rows[0][0] == "E1001");
    assert(seed_authority_result.rows[0][1] == "Cybersecurity");
    const auto one_employee = mapped.universal_lookup(
        {"Employee ID", "Username", "Email"}, "E1001");
    assert(one_employee.rows.size() == 1);
    assert(one_employee.rows[0][0] == "E1001");
    assert(one_employee.rows[0][1] == "speela");
    assert(one_employee.rows[0][2] == "sunil@example.com");
    const auto missing_lookup = mapped.universal_lookup(
        {"Username"}, "COMPUTER-DOES-NOT-EXIST");
    assert(missing_lookup.rows.empty());

    const auto zero_users = root / "ZeroPaddedUsers.csv";
    const auto zero_devices = root / "UnpaddedDevices.csv";
    {
        std::ofstream out(zero_users);
        out << "Employee ID,Username\n00039929,zero.user\n";
    }
    {
        std::ofstream out(zero_devices);
        out << "Associate Number,Computer Name\n39929,PC-ZERO\n";
    }
    point::Engine zero_engine;
    zero_engine.set_field_synonyms({
        {"Employee ID", {"Associate Number"}}
    });
    zero_engine.load_files({zero_users, zero_devices});
    assert(zero_engine.relationships().size() == 1);
    const auto short_eid = zero_engine.universal_lookup(
        {"Username"}, "39929");
    assert(short_eid.rows.size() == 1);
    assert(short_eid.rows[0][0] == "zero.user");
    point::QueryRequest short_eid_request;
    short_eid_request.lookup_field = "Employee ID";
    short_eid_request.lookup_value = "39929";
    short_eid_request.output_fields = {"Username"};
    const auto direct_short_eid = zero_engine.query(short_eid_request);
    assert(direct_short_eid.rows.size() == 1);
    assert(direct_short_eid.rows[0][0] == "zero.user");
    const auto padded_eid = zero_engine.universal_lookup(
        {"Computer Name"}, "00039929");
    assert(padded_eid.rows.size() == 1);
    assert(padded_eid.rows[0][0] == "PC-ZERO");
    const auto preserved_eid = zero_engine.universal_lookup(
        {"Employee ID"}, "zero.user");
    assert(preserved_eid.rows.size() == 1);
    assert(preserved_eid.rows[0][0] == "00039929");

    const auto group_memberships = root / "GroupMemberships.csv";
    const auto group_catalog = root / "GroupCatalog.csv";
    {
        std::ofstream out(group_memberships);
        out << "Employee ID,Group ID,Group Name\n"
               "E000004,G0106,Legal Standard Access\n";
    }
    {
        std::ofstream out(group_catalog);
        out << "Group ID,Group Name,Group Owner\n"
               "G0106,Legal Standard Access,Legal\n";
    }
    point::Engine group_engine;
    group_engine.load_files({group_memberships, group_catalog});
    assert(!group_engine.relationships().empty());
    point::QueryRequest owner_request;
    owner_request.lookup_field = "Employee ID";
    owner_request.lookup_value = "E000004";
    owner_request.output_fields = {
        "Group ID", "Group Name", "Group Owner"};
    const auto owner_result = group_engine.query(owner_request);
    assert(owner_result.rows.size() == 1);
    assert(owner_result.rows[0][0] == "G0106");
    assert(owner_result.rows[0][2] == "Legal");

    const auto unsafe_groups_left = root / "UnsafeGroupsLeft.csv";
    const auto unsafe_groups_right = root / "UnsafeGroupsRight.csv";
    {
        std::ofstream out(unsafe_groups_left);
        out << "Group ID,Left Value\nG1,A\nG1,B\n";
    }
    {
        std::ofstream out(unsafe_groups_right);
        out << "Group ID,Right Value\nG1,C\nG1,D\n";
    }
    point::Engine unsafe_group_engine;
    unsafe_group_engine.load_files({unsafe_groups_left, unsafe_groups_right});
    assert(unsafe_group_engine.relationships().empty());

    const auto request_assignments = root / "RequestAssignments.csv";
    const auto request_catalog = root / "RequestCatalog.csv";
    {
        std::ofstream out(request_assignments);
        out << "Employee ID,Request Code\nE000004,R-42\n";
    }
    {
        std::ofstream out(request_catalog);
        out << "Request Code,Approver\nR-42,Security Manager\n";
    }
    point::Engine generic_catalog_engine;
    generic_catalog_engine.load_files({request_assignments, request_catalog});
    point::QueryRequest approver_request;
    approver_request.lookup_field = "Employee ID";
    approver_request.lookup_value = "E000004";
    approver_request.output_fields = {"Request Code", "Approver"};
    const auto approver_result = generic_catalog_engine.query(approver_request);
    assert(approver_result.rows.size() == 1);
    assert(approver_result.rows[0][1] == "Security Manager");

    const auto duplicates = root / "DuplicateNames.csv";
    {
        std::ofstream out(duplicates);
        out << "Employee ID,Username,Display Name\n"
               "E2001,alex.one,Alex Lee\n"
               "E2002,alex.two,Lee Alex\n";
    }
    point::Engine ambiguous_engine;
    ambiguous_engine.load_files({duplicates});
    const auto ambiguous = ambiguous_engine.resolve_identity_from_name(
        "Username", "Alex Lee");
    assert(ambiguous.status ==
        point::IdentityResolutionStatus::Ambiguous);
    assert(ambiguous.distinct_matches == 2);
    const auto ambiguous_lookup = ambiguous_engine.universal_lookup(
        {"Employee ID", "Username", "Display Name"}, "Alex Lee");
    assert(ambiguous_lookup.rows.empty());
    assert(ambiguous_lookup.explanation.find("multiple people") !=
        std::string::npos);

    const auto repeated_person_a = root / "RepeatedPersonA.csv";
    const auto repeated_person_b = root / "RepeatedPersonB.csv";
    {
        std::ofstream out(repeated_person_a);
        out << "Employee ID,Username,Display Name,Department\n"
               "E4100,speela,\"Peela, Sunil\",Security\n";
    }
    {
        std::ofstream out(repeated_person_b);
        out << "Employee ID,Username,First Name,Last Name,Computer Name\n"
               "E4100,speela,Sunil,Peela,PC-4100\n";
    }
    point::Engine repeated_person_engine;
    repeated_person_engine.load_files(
        {repeated_person_a, repeated_person_b});
    const auto safe_full_name = repeated_person_engine.universal_lookup(
        {"Employee ID", "Username", "Computer Name"}, "Sunil Peela");
    assert(safe_full_name.rows.size() == 1);
    assert(safe_full_name.rows[0][0] == "E4100");
    assert(safe_full_name.rows[0][1] == "speela");
    assert(safe_full_name.rows[0][2] == "PC-4100");

    const auto shared_surname = root / "SharedSurname.csv";
    {
        std::ofstream out(shared_surname);
        out << "Employee ID,Username,First Name,Last Name\n"
               "E4201,sam.lee,Sam,Lee\n"
               "E4202,alex.lee,Alex,Lee\n";
    }
    point::Engine shared_surname_engine;
    shared_surname_engine.load_files({shared_surname});
    const auto unsafe_surname = shared_surname_engine.universal_lookup(
        {"Employee ID", "Username"}, "Lee");
    assert(unsafe_surname.rows.empty());
    assert(unsafe_surname.explanation.find("multiple people") !=
        std::string::npos);

    const auto blank_leading_header = root / "BlankLeadingHeader.csv";
    {
        std::ofstream out(blank_leading_header);
        out << ",First Name,Last Name,Gender,Country,Age,Date,Id\n"
               "1,Dulce,Abril,Female,United States,32,15/10/2017,1562\n";
    }
    point::Engine blank_header_engine;
    blank_header_engine.load_files({blank_leading_header});
    assert(blank_header_engine.issues().empty());
    assert(blank_header_engine.all_fields().size() == 8);
    point::QueryRequest blank_header_request;
    blank_header_request.lookup_field = "Id";
    blank_header_request.lookup_value = "1562";
    blank_header_request.output_fields = {
        "Unnamed Column 1", "First Name", "Last Name"};
    const auto blank_header_result =
        blank_header_engine.query(blank_header_request);
    assert(blank_header_result.rows.size() == 1);
    assert(blank_header_result.rows[0][0] == "1");
    assert(blank_header_result.rows[0][1] == "Dulce");
    assert(blank_header_result.rows[0][2] == "Abril");

    const auto unique_first_names = root / "UniqueFirstNames.csv";
    const auto repeated_first_names = root / "RepeatedFirstNames.csv";
    {
        std::ofstream out(unique_first_names);
        out << "First Name,Last Name\nAlice,One\nBob,Two\n";
    }
    {
        std::ofstream out(repeated_first_names);
        out << "First Name,Last Name\n"
               "Shanice,Mccrystal\nShanice,Mccrystal\n";
    }
    point::Engine mixed_uniqueness_engine;
    mixed_uniqueness_engine.load_files(
        {unique_first_names, repeated_first_names});
    const auto shanice_result = mixed_uniqueness_engine.universal_lookup(
        {"First Name", "Last Name"}, "Shanice");
    assert(!shanice_result.rows.empty());
    assert(shanice_result.rows[0][0] == "Shanice");
    assert(shanice_result.rows[0][1] == "Mccrystal");

    const auto date_fields = root / "DateFieldPriority.csv";
    {
        std::ofstream out(date_fields);
        out << "Order Date,Ship Date,Order ID,City\n"
               "44933,44938,US-2023-105417,Huntsville\n"
               "44929,44933,US-2023-103800,Houston\n"
               "44932,44933,US-2023-106054,Athens\n";
    }
    point::Engine date_priority_engine;
    date_priority_engine.load_files({date_fields});
    const auto broad_date_result = date_priority_engine.universal_lookup(
        {"Order Date", "City", "Order ID", "Ship Date"}, "44933");
    assert(broad_date_result.rows.size() == 3);
    point::QueryRequest preferred_date_request;
    preferred_date_request.output_fields =
        {"Order Date", "City", "Order ID", "Ship Date"};
    preferred_date_request.conditions.push_back({"Order Date", "44933"});
    const auto preferred_date_result =
        date_priority_engine.query(preferred_date_request);
    assert(preferred_date_result.rows.size() == 1);
    assert(preferred_date_result.rows[0][2] == "US-2023-105417");

    point::Engine contextual_synonym_engine;
    contextual_synonym_engine.set_field_synonyms({
        {"Department", {"Business Unit"}}
    });

    bool conflict_rejected = false;
    try {
        mapped.set_field_synonyms({
            {"Employee ID", {"Worker Number"}},
            {"User ID", {"Worker Number"}}
        });
    } catch (...) {
        conflict_rejected = true;
    }
    assert(conflict_rejected);

    const std::vector<std::string> assistant_fields = {
        "SAM Account Name", "Display Name", "Group Name", "Computer Name",
        "Operating System", "Computer Status", "BitLocker Status", "Department"};
    const auto group_plan = point::plan_assistant_request(
        "show groups for speela", assistant_fields);
    assert(group_plan.mode == point::AssistantMode::Universal);
    assert(group_plan.inputs == std::vector<std::string>{"speela"});
    assert(group_plan.fields.size() == 3);
    const auto compare_plan = point::plan_assistant_request(
        "compare groups for speela and jsmith", assistant_fields);
    assert(compare_plan.mode == point::AssistantMode::Compare);
    assert(compare_plan.inputs.size() == 2);
    assert(compare_plan.inputs[0] == "speela");
    assert(compare_plan.inputs[1] == "jsmith");
    const auto computer_plan = point::plan_assistant_request(
        "computer details for speela", assistant_fields);
    assert(computer_plan.fields.size() == 5);
    const auto count_plan = point::plan_assistant_request(
        "count by department", assistant_fields);
    assert(count_plan.mode == point::AssistantMode::Count);
    assert(count_plan.fields[0] == "Department");

    point::QueryResult risk_evidence;
    risk_evidence.headers = {
        "Computer Name", "Operating System", "BitLocker Status",
        "Computer Status", "Group Name"};
    risk_evidence.rows = {{
        "PC-001", "Windows 7 Enterprise", "Disabled", "Inactive",
        "Domain Admins"}};
    const auto risk = point::assess_offline_risk("PC-001", risk_evidence);
    assert(risk.rating == "High");
    assert(risk.maximum_score == 8.8);
    assert(risk.findings.size() == 4);
    assert(!risk.has_authoritative_cvss);
    point::QueryResult cvss_evidence;
    cvss_evidence.headers = {"Computer Name", "CVSS Score"};
    cvss_evidence.rows = {{"PC-002", "9.8"}};
    const auto cvss_risk = point::assess_offline_risk("PC-002", cvss_evidence);
    assert(cvss_risk.rating == "Critical");
    assert(cvss_risk.has_authoritative_cvss);

    const auto change_ledger = root / "ChangeLedger.csv";
    {
        std::ofstream out(change_ledger);
        out << "Employee ID,Display Name,Department,Status\n"
               "E1,Sunil Peela,IT,Active\n"
               "E2,John Smith,HR,Active\n";
    }
    point::Engine change_baseline;
    change_baseline.load_files({change_ledger});
    {
        std::ofstream out(change_ledger);
        out << "Employee ID,Display Name,Department,Status\n"
               "E1,Sunil Peela,Security,Disabled\n"
               "E3,Grace Doe,IT,Active\n";
    }
    point::Engine change_current;
    change_current.load_files({change_ledger});
    const auto observed_changes = change_current.changes_since(
        change_baseline, {"Employee ID"});
    assert(observed_changes.rows.size() == 8);
    assert(std::none_of(
        observed_changes.rows.begin(), observed_changes.rows.end(),
        [](const auto& row) { return row[0] == "Unchanged"; }));
    std::set<std::string> modified_fields;
    for (const auto& row : observed_changes.rows)
        if (row[0] == "Modified") modified_fields.insert(row[3]);
    assert(modified_fields == std::set<std::string>({"Department", "Status"}));
    const auto no_changes = change_current.changes_since(
        change_current, {"Employee ID"});
    assert(no_changes.rows.empty());
    const auto automatic_changes = change_current.changes_since_auto(
        change_baseline);
    assert(automatic_changes.rows.size() == observed_changes.rows.size());
    assert(automatic_changes.headers == observed_changes.headers);
    const auto automatic_no_changes = change_current.changes_since_auto(
        change_current);
    assert(automatic_no_changes.rows.empty());

    std::filesystem::remove_all(root);
    std::cout << "schema mapping tests passed\n";
}
