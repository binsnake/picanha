#include "picanha/persistence/database.hpp"
#include <spdlog/spdlog.h>

namespace picanha::persistence {

// Statement implementation
Statement::~Statement() {
    if (stmt_) {
        sqlite3_finalize(stmt_);
    }
}

Statement::Statement(Statement&& other) noexcept
    : stmt_(other.stmt_)
{
    other.stmt_ = nullptr;
}

Statement& Statement::operator=(Statement&& other) noexcept {
    if (this != &other) {
        if (stmt_) {
            sqlite3_finalize(stmt_);
        }
        stmt_ = other.stmt_;
        other.stmt_ = nullptr;
    }
    return *this;
}

bool Statement::bind(int index, int value) {
    return sqlite3_bind_int(stmt_, index, value) == SQLITE_OK;
}

bool Statement::bind(int index, std::int64_t value) {
    return sqlite3_bind_int64(stmt_, index, value) == SQLITE_OK;
}

bool Statement::bind(int index, double value) {
    return sqlite3_bind_double(stmt_, index, value) == SQLITE_OK;
}

bool Statement::bind(int index, const std::string& value) {
    return sqlite3_bind_text(stmt_, index, value.c_str(),
                             static_cast<int>(value.size()), SQLITE_TRANSIENT) == SQLITE_OK;
}

bool Statement::bind(int index, std::string_view value) {
    return sqlite3_bind_text(stmt_, index, value.data(),
                             static_cast<int>(value.size()), SQLITE_TRANSIENT) == SQLITE_OK;
}

bool Statement::bind(int index, const void* data, std::size_t size) {
    return sqlite3_bind_blob(stmt_, index, data,
                             static_cast<int>(size), SQLITE_TRANSIENT) == SQLITE_OK;
}

bool Statement::bind_null(int index) {
    return sqlite3_bind_null(stmt_, index) == SQLITE_OK;
}

bool Statement::bind(const char* name, int value) {
    int index = sqlite3_bind_parameter_index(stmt_, name);
    return index > 0 && bind(index, value);
}

bool Statement::bind(const char* name, std::int64_t value) {
    int index = sqlite3_bind_parameter_index(stmt_, name);
    return index > 0 && bind(index, value);
}

bool Statement::bind(const char* name, const std::string& value) {
    int index = sqlite3_bind_parameter_index(stmt_, name);
    return index > 0 && bind(index, value);
}

bool Statement::step() {
    int rc = sqlite3_step(stmt_);
    return rc == SQLITE_ROW;
}

bool Statement::execute() {
    int rc = sqlite3_step(stmt_);
    return rc == SQLITE_DONE || rc == SQLITE_ROW;
}

void Statement::reset() {
    sqlite3_reset(stmt_);
    sqlite3_clear_bindings(stmt_);
}

int Statement::column_count() const {
    return sqlite3_column_count(stmt_);
}

int Statement::column_int(int col) const {
    return sqlite3_column_int(stmt_, col);
}

std::int64_t Statement::column_int64(int col) const {
    return sqlite3_column_int64(stmt_, col);
}

double Statement::column_double(int col) const {
    return sqlite3_column_double(stmt_, col);
}

std::string Statement::column_text(int col) const {
    const unsigned char* text = sqlite3_column_text(stmt_, col);
    if (!text) return "";
    return reinterpret_cast<const char*>(text);
}

std::string_view Statement::column_text_view(int col) const {
    const unsigned char* text = sqlite3_column_text(stmt_, col);
    if (!text) return "";
    int bytes = sqlite3_column_bytes(stmt_, col);
    return {reinterpret_cast<const char*>(text), static_cast<std::size_t>(bytes)};
}

const void* Statement::column_blob(int col) const {
    return sqlite3_column_blob(stmt_, col);
}

int Statement::column_bytes(int col) const {
    return sqlite3_column_bytes(stmt_, col);
}

bool Statement::column_is_null(int col) const {
    return sqlite3_column_type(stmt_, col) == SQLITE_NULL;
}

// Transaction implementation
Transaction::Transaction(Database& db)
    : db_(db)
{
    auto result = db_.begin_transaction();
    if (!result) {
        spdlog::error("Failed to begin transaction: {}", db_.last_error());
    }
}

Transaction::~Transaction() {
    if (!committed_ && !rolled_back_) {
        rollback();
    }
}

void Transaction::commit() {
    if (!committed_ && !rolled_back_) {
        auto result = db_.commit();
        if (!result) {
            spdlog::error("Failed to commit transaction: {}", db_.last_error());
        }
        committed_ = true;
    }
}

void Transaction::rollback() {
    if (!committed_ && !rolled_back_) {
        auto result = db_.rollback();
        if (!result) {
            spdlog::error("Failed to rollback transaction: {}", db_.last_error());
        }
        rolled_back_ = true;
    }
}

// Database implementation
Database::~Database() {
    close();
}

Result<void> Database::open(const std::string& path) {
    if (db_) {
        close();
    }

    int rc = sqlite3_open(path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        std::string error = sqlite3_errmsg(db_);
        sqlite3_close(db_);
        db_ = nullptr;
        return std::unexpected(io_error("Failed to open database: " + error));
    }

    path_ = path;

    // Enable foreign keys
    execute("PRAGMA foreign_keys = ON");

    // Set journal mode to WAL for better concurrency
    execute("PRAGMA journal_mode = WAL");

    return {};
}

Result<void> Database::create(const std::string& path) {
    auto result = open(path);
    if (!result) return result;

    return create_schema();
}

void Database::close() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
        path_.clear();
    }
}

Result<void> Database::create_schema() {
    Transaction txn(*this);

    for (const auto& sql : sql::ALL_CREATE_TABLES) {
        auto result = execute(sql);
        if (!result) {
            return result;
        }
    }

    // Set schema version
    auto result = execute(
        "INSERT OR REPLACE INTO analysis_state (key, value) VALUES ('schema_version', '" +
        std::to_string(SCHEMA_VERSION) + "')"
    );
    if (!result) return result;

    txn.commit();
    return {};
}

Result<std::uint32_t> Database::get_schema_version() {
    auto version = query_scalar<std::string>(
        "SELECT value FROM analysis_state WHERE key = 'schema_version'"
    );

    if (!version) {
        return std::unexpected(database_error("Schema version not found"));
    }

    try {
        return static_cast<std::uint32_t>(std::stoul(*version));
    } catch (...) {
        return std::unexpected(parse_error("Invalid schema version"));
    }
}

Result<void> Database::migrate_schema(std::uint32_t from_version) {
    // Migration logic would go here
    // For now, just update the version
    if (from_version < SCHEMA_VERSION) {
        spdlog::info("Migrating database schema from {} to {}",
                     from_version, SCHEMA_VERSION);

        // Add migration steps as needed

        auto result = execute(
            "UPDATE analysis_state SET value = '" +
            std::to_string(SCHEMA_VERSION) +
            "' WHERE key = 'schema_version'"
        );
        if (!result) return result;
    }

    return {};
}

Result<Statement> Database::prepare(std::string_view sql) {
    if (!db_) {
        return std::unexpected(internal_error("Database not open"));
    }

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql.data(), static_cast<int>(sql.size()),
                                &stmt, nullptr);

    if (rc != SQLITE_OK) {
        return std::unexpected(database_error(
            std::string("Failed to prepare statement: ") + sqlite3_errmsg(db_)));
    }

    return Statement(stmt);
}

Result<void> Database::execute(std::string_view sql) {
    if (!db_) {
        return std::unexpected(internal_error("Database not open"));
    }

    char* error_msg = nullptr;
    int rc = sqlite3_exec(db_, std::string(sql).c_str(), nullptr, nullptr, &error_msg);

    if (rc != SQLITE_OK) {
        std::string error = error_msg ? error_msg : "Unknown error";
        sqlite3_free(error_msg);
        return std::unexpected(database_error("Execute failed: " + error));
    }

    return {};
}

Result<void> Database::execute(const Statement& stmt) {
    if (!stmt.is_valid()) {
        return std::unexpected(internal_error("Invalid statement"));
    }

    int rc = sqlite3_step(stmt.handle());
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        return std::unexpected(database_error(
            std::string("Execute failed: ") + sqlite3_errmsg(db_)));
    }

    return {};
}

Result<void> Database::begin_transaction() {
    return execute("BEGIN TRANSACTION");
}

Result<void> Database::commit() {
    return execute("COMMIT");
}

Result<void> Database::rollback() {
    return execute("ROLLBACK");
}

std::int64_t Database::last_insert_rowid() const {
    return db_ ? sqlite3_last_insert_rowid(db_) : 0;
}

int Database::changes() const {
    return db_ ? sqlite3_changes(db_) : 0;
}

const char* Database::last_error() const {
    return db_ ? sqlite3_errmsg(db_) : "Database not open";
}

Result<void> Database::query(std::string_view sql, RowCallback callback) {
    auto stmt_result = prepare(sql);
    if (!stmt_result) return std::unexpected(stmt_result.error());

    auto& stmt = *stmt_result;
    while (stmt.step()) {
        if (!callback(stmt)) {
            break;
        }
    }

    return {};
}

} // namespace picanha::persistence
