#pragma once

#include "picanha/persistence/database.hpp"
#include <picanha/core/types.hpp>
#include <picanha/core/result.hpp>
#include <picanha/loader/binary.hpp>
#include <picanha/analysis/function.hpp>
#include <picanha/analysis/cfg.hpp>
#include <picanha/analysis/symbol_table.hpp>
#include <picanha/analysis/xref_manager.hpp>
#include <picanha/analysis/jump_table.hpp>
#include <memory>
#include <string>
#include <chrono>
#include <filesystem>
#include <functional>

namespace picanha::persistence {

// Project metadata
struct ProjectInfo {
    std::string name;
    std::string description;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point modified_at;
    std::uint32_t schema_version{SCHEMA_VERSION};

    // Binary info
    std::string binary_path;
    std::string binary_hash;
    Address image_base{0};
    Address entry_point{0};
};

// Comment stored in project
struct Comment {
    Address address;
    CommentType type;
    std::string text;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point modified_at;
};

// Bookmark stored in project
struct Bookmark {
    Address address;
    std::string name;
    std::string description;
    std::uint32_t color{0};
    std::chrono::system_clock::time_point created_at;
};

// Progress callback for save/load operations
using ProjectProgressCallback = std::function<void(float progress, const char* phase)>;

// Project file manager
class Project {
public:
    Project();
    ~Project();

    // Create new project
    [[nodiscard]] Result<void> create(
        const std::filesystem::path& path,
        const std::string& name
    );

    // Open existing project
    [[nodiscard]] Result<void> open(const std::filesystem::path& path);

    // Save project
    [[nodiscard]] Result<void> save();
    [[nodiscard]] Result<void> save_as(const std::filesystem::path& path);

    // Close project
    void close();

    // Check state
    [[nodiscard]] bool is_open() const { return db_.is_open(); }
    [[nodiscard]] bool is_modified() const { return modified_; }
    [[nodiscard]] const std::filesystem::path& path() const { return path_; }

    // Project info
    [[nodiscard]] const ProjectInfo& info() const { return info_; }
    void set_name(const std::string& name);
    void set_description(const std::string& description);

    // Binary association
    [[nodiscard]] Result<void> set_binary(std::shared_ptr<loader::Binary> binary);
    [[nodiscard]] std::shared_ptr<loader::Binary> binary() const { return binary_; }

    // Save/load analysis data
    [[nodiscard]] Result<void> save_functions(
        const std::vector<analysis::Function>& functions,
        ProjectProgressCallback callback = nullptr
    );

    [[nodiscard]] Result<std::vector<analysis::Function>> load_functions(
        ProjectProgressCallback callback = nullptr
    );

    [[nodiscard]] Result<void> save_symbols(
        const analysis::SymbolTable& symbols,
        ProjectProgressCallback callback = nullptr
    );

    [[nodiscard]] Result<void> load_symbols(
        analysis::SymbolTable& symbols,
        ProjectProgressCallback callback = nullptr
    );

    [[nodiscard]] Result<void> save_xrefs(
        const analysis::XRefManager& xrefs,
        ProjectProgressCallback callback = nullptr
    );

    [[nodiscard]] Result<void> load_xrefs(
        analysis::XRefManager& xrefs,
        ProjectProgressCallback callback = nullptr
    );

    [[nodiscard]] Result<void> save_jump_tables(
        const std::vector<analysis::JumpTable>& tables
    );

    [[nodiscard]] Result<std::vector<analysis::JumpTable>> load_jump_tables();

    // Comments
    [[nodiscard]] Result<void> add_comment(const Comment& comment);
    [[nodiscard]] Result<void> update_comment(Address address, const std::string& text);
    [[nodiscard]] Result<void> delete_comment(Address address);
    [[nodiscard]] Result<std::optional<Comment>> get_comment(Address address);
    [[nodiscard]] Result<std::vector<Comment>> get_all_comments();

    // Bookmarks
    [[nodiscard]] Result<void> add_bookmark(const Bookmark& bookmark);
    [[nodiscard]] Result<void> delete_bookmark(Address address);
    [[nodiscard]] Result<std::vector<Bookmark>> get_all_bookmarks();

    // Analysis state (key-value storage)
    [[nodiscard]] Result<void> set_state(const std::string& key, const std::string& value);
    [[nodiscard]] Result<std::optional<std::string>> get_state(const std::string& key);

    // Direct database access (for advanced use)
    [[nodiscard]] Database& database() { return db_; }

private:
    // Load project info from database
    [[nodiscard]] Result<void> load_info();

    // Save project info to database
    [[nodiscard]] Result<void> save_info();

    // Compute binary hash
    [[nodiscard]] std::string compute_binary_hash() const;

    Database db_;
    std::filesystem::path path_;
    ProjectInfo info_;
    std::shared_ptr<loader::Binary> binary_;
    bool modified_{false};
};

// Utility: compute file hash
[[nodiscard]] std::string compute_file_hash(const std::filesystem::path& path);

} // namespace picanha::persistence
