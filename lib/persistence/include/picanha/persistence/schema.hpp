#pragma once

#include <cstdint>
#include <string_view>

namespace picanha::persistence {

// Database schema version for migrations
constexpr std::uint32_t SCHEMA_VERSION = 1;

// Project file magic number
constexpr std::uint32_t PROJECT_MAGIC = 0x50494341;  // "PICA"

// SQL statements for creating tables
namespace sql {

// Project metadata table
constexpr std::string_view CREATE_PROJECT_TABLE = R"(
    CREATE TABLE IF NOT EXISTS project (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        created_at INTEGER NOT NULL,
        modified_at INTEGER NOT NULL,
        schema_version INTEGER NOT NULL,
        binary_path TEXT,
        binary_hash TEXT,
        image_base INTEGER,
        entry_point INTEGER
    )
)";

// Binary sections
constexpr std::string_view CREATE_SECTIONS_TABLE = R"(
    CREATE TABLE IF NOT EXISTS sections (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        virtual_address INTEGER NOT NULL,
        virtual_size INTEGER NOT NULL,
        raw_address INTEGER NOT NULL,
        raw_size INTEGER NOT NULL,
        characteristics INTEGER NOT NULL
    )
)";

// Functions table
constexpr std::string_view CREATE_FUNCTIONS_TABLE = R"(
    CREATE TABLE IF NOT EXISTS functions (
        id INTEGER PRIMARY KEY,
        entry_address INTEGER NOT NULL UNIQUE,
        name TEXT,
        type INTEGER NOT NULL DEFAULT 0,
        calling_conv INTEGER NOT NULL DEFAULT 0,
        flags INTEGER NOT NULL DEFAULT 0,
        stack_frame_size INTEGER DEFAULT 0,
        local_vars_size INTEGER DEFAULT 0,
        args_size INTEGER DEFAULT 0
    )
)";

// Function index for address lookup
constexpr std::string_view CREATE_FUNCTIONS_INDEX = R"(
    CREATE INDEX IF NOT EXISTS idx_functions_address ON functions(entry_address)
)";

// Basic blocks table
constexpr std::string_view CREATE_BLOCKS_TABLE = R"(
    CREATE TABLE IF NOT EXISTS blocks (
        id INTEGER PRIMARY KEY,
        function_id INTEGER NOT NULL,
        start_address INTEGER NOT NULL,
        end_address INTEGER NOT NULL,
        is_entry INTEGER NOT NULL DEFAULT 0,
        is_exit INTEGER NOT NULL DEFAULT 0,
        has_call INTEGER NOT NULL DEFAULT 0,
        has_indirect INTEGER NOT NULL DEFAULT 0,
        idom_id INTEGER,
        FOREIGN KEY (function_id) REFERENCES functions(id) ON DELETE CASCADE
    )
)";

constexpr std::string_view CREATE_BLOCKS_INDEX = R"(
    CREATE INDEX IF NOT EXISTS idx_blocks_function ON blocks(function_id)
)";

constexpr std::string_view CREATE_BLOCKS_ADDR_INDEX = R"(
    CREATE INDEX IF NOT EXISTS idx_blocks_address ON blocks(start_address)
)";

// Block edges table
constexpr std::string_view CREATE_EDGES_TABLE = R"(
    CREATE TABLE IF NOT EXISTS block_edges (
        id INTEGER PRIMARY KEY,
        from_block_id INTEGER NOT NULL,
        to_block_id INTEGER NOT NULL,
        edge_type INTEGER NOT NULL,
        is_back_edge INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY (from_block_id) REFERENCES blocks(id) ON DELETE CASCADE,
        FOREIGN KEY (to_block_id) REFERENCES blocks(id) ON DELETE CASCADE
    )
)";

// Symbols table
constexpr std::string_view CREATE_SYMBOLS_TABLE = R"(
    CREATE TABLE IF NOT EXISTS symbols (
        id INTEGER PRIMARY KEY,
        address INTEGER NOT NULL,
        size INTEGER NOT NULL DEFAULT 0,
        name TEXT NOT NULL,
        demangled_name TEXT,
        module_name TEXT,
        type INTEGER NOT NULL DEFAULT 0,
        visibility INTEGER NOT NULL DEFAULT 0,
        source INTEGER NOT NULL DEFAULT 0,
        flags INTEGER NOT NULL DEFAULT 0,
        function_id INTEGER,
        ordinal INTEGER DEFAULT 0,
        FOREIGN KEY (function_id) REFERENCES functions(id) ON DELETE SET NULL
    )
)";

constexpr std::string_view CREATE_SYMBOLS_INDEX = R"(
    CREATE INDEX IF NOT EXISTS idx_symbols_address ON symbols(address)
)";

constexpr std::string_view CREATE_SYMBOLS_NAME_INDEX = R"(
    CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name)
)";

// Cross-references table
constexpr std::string_view CREATE_XREFS_TABLE = R"(
    CREATE TABLE IF NOT EXISTS xrefs (
        id INTEGER PRIMARY KEY,
        from_address INTEGER NOT NULL,
        to_address INTEGER NOT NULL,
        type INTEGER NOT NULL,
        flow INTEGER NOT NULL DEFAULT 0,
        from_func_id INTEGER,
        to_func_id INTEGER,
        from_block_id INTEGER,
        to_block_id INTEGER,
        is_user_defined INTEGER NOT NULL DEFAULT 0,
        is_indirect INTEGER NOT NULL DEFAULT 0,
        is_conditional INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY (from_func_id) REFERENCES functions(id) ON DELETE SET NULL,
        FOREIGN KEY (to_func_id) REFERENCES functions(id) ON DELETE SET NULL
    )
)";

constexpr std::string_view CREATE_XREFS_FROM_INDEX = R"(
    CREATE INDEX IF NOT EXISTS idx_xrefs_from ON xrefs(from_address)
)";

constexpr std::string_view CREATE_XREFS_TO_INDEX = R"(
    CREATE INDEX IF NOT EXISTS idx_xrefs_to ON xrefs(to_address)
)";

// Comments table
constexpr std::string_view CREATE_COMMENTS_TABLE = R"(
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY,
        address INTEGER NOT NULL,
        type INTEGER NOT NULL DEFAULT 0,
        text TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        modified_at INTEGER NOT NULL
    )
)";

constexpr std::string_view CREATE_COMMENTS_INDEX = R"(
    CREATE INDEX IF NOT EXISTS idx_comments_address ON comments(address)
)";

// User-defined types/structs
constexpr std::string_view CREATE_TYPES_TABLE = R"(
    CREATE TABLE IF NOT EXISTS user_types (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        kind INTEGER NOT NULL,
        size INTEGER NOT NULL DEFAULT 0,
        definition TEXT
    )
)";

// Jump tables
constexpr std::string_view CREATE_JUMP_TABLES_TABLE = R"(
    CREATE TABLE IF NOT EXISTS jump_tables (
        id INTEGER PRIMARY KEY,
        table_address INTEGER NOT NULL,
        instruction_address INTEGER NOT NULL,
        base_address INTEGER,
        entry_count INTEGER NOT NULL,
        entry_size INTEGER NOT NULL,
        entry_type INTEGER NOT NULL,
        confidence INTEGER NOT NULL DEFAULT 0
    )
)";

// Jump table entries
constexpr std::string_view CREATE_JUMP_TABLE_ENTRIES_TABLE = R"(
    CREATE TABLE IF NOT EXISTS jump_table_entries (
        id INTEGER PRIMARY KEY,
        table_id INTEGER NOT NULL,
        index_value INTEGER NOT NULL,
        target_address INTEGER NOT NULL,
        FOREIGN KEY (table_id) REFERENCES jump_tables(id) ON DELETE CASCADE
    )
)";

// Bookmarks
constexpr std::string_view CREATE_BOOKMARKS_TABLE = R"(
    CREATE TABLE IF NOT EXISTS bookmarks (
        id INTEGER PRIMARY KEY,
        address INTEGER NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        color INTEGER DEFAULT 0,
        created_at INTEGER NOT NULL
    )
)";

// Analysis state/metadata
constexpr std::string_view CREATE_ANALYSIS_STATE_TABLE = R"(
    CREATE TABLE IF NOT EXISTS analysis_state (
        key TEXT PRIMARY KEY,
        value TEXT
    )
)";

// List of all table creation statements
constexpr std::string_view ALL_CREATE_TABLES[] = {
    CREATE_PROJECT_TABLE,
    CREATE_SECTIONS_TABLE,
    CREATE_FUNCTIONS_TABLE,
    CREATE_FUNCTIONS_INDEX,
    CREATE_BLOCKS_TABLE,
    CREATE_BLOCKS_INDEX,
    CREATE_BLOCKS_ADDR_INDEX,
    CREATE_EDGES_TABLE,
    CREATE_SYMBOLS_TABLE,
    CREATE_SYMBOLS_INDEX,
    CREATE_SYMBOLS_NAME_INDEX,
    CREATE_XREFS_TABLE,
    CREATE_XREFS_FROM_INDEX,
    CREATE_XREFS_TO_INDEX,
    CREATE_COMMENTS_TABLE,
    CREATE_COMMENTS_INDEX,
    CREATE_TYPES_TABLE,
    CREATE_JUMP_TABLES_TABLE,
    CREATE_JUMP_TABLE_ENTRIES_TABLE,
    CREATE_BOOKMARKS_TABLE,
    CREATE_ANALYSIS_STATE_TABLE,
};

} // namespace sql

// Comment types
enum class CommentType : std::uint8_t {
    Regular,        // Regular comment at address
    Repeatable,     // Repeatable comment (shows at all refs)
    Anterior,       // Comment before line
    Posterior,      // Comment after line
    Function,       // Function-level comment
};

// User type kinds
enum class UserTypeKind : std::uint8_t {
    Typedef,
    Struct,
    Union,
    Enum,
    Function,
};

} // namespace picanha::persistence
