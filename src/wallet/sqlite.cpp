// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/sqlite.h>

#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/db.h>

#include <sqlite3.h>
#include <stdint.h>
#include <sqlite3.h>
#include <unordered_set>

namespace {
    RecursiveMutex cs_sqlite;
    //! Set of wallet file paths in use
    std::unordered_set<std::string> g_file_paths GUARDED_BY(cs_sqlite);
} // namespace

bool IsSQLiteWalletLoaded(const fs::path& wallet_path)
{
    fs::path data_path = WalletDataFilePath(wallet_path);
    LOCK(cs_sqlite);
    return g_file_paths.count(data_path.string()) > 0;
}

bool SQLiteDatabase::Verify(bilingual_str& error)
{
    if (!PrepareDirectory()) return false;

    return false;
}

static void ErrorLogCallback(void* arg, int code, const char* msg)
{
    assert(arg == nullptr); // That's what we tell it to do during the setup
    LogPrintf("SQLite Error. Code: %d. Message: %s\n", code, msg);
}

SQLiteDatabase::SQLiteDatabase(const fs::path& dir_path, const fs::path& file_path, bool mock) :
    WalletDatabase(), m_mock(mock), m_db(nullptr), m_file_path(file_path.string()), m_dir_path(dir_path.string())
{
    LogPrintf("Using SQLite Version %s\n", SQLiteDatabaseVersion());
    LogPrintf("Using wallet %s\n", m_dir_path);

    LOCK(cs_sqlite);
    if (g_file_paths.empty()) {
        // Setup logging
        int ret = sqlite3_config(SQLITE_CONFIG_LOG, ErrorLogCallback, nullptr);
        if (ret != SQLITE_OK) {
            throw std::runtime_error(strprintf("SQLiteDatabase: Failed to setup error log: %s\n", sqlite3_errstr(ret)));
        }
    }
    int ret = sqlite3_initialize();
    if (ret != SQLITE_OK) {
        throw std::runtime_error(strprintf("SQLiteDatabase: Failed to initialize SQLite: %s\n", sqlite3_errstr(ret)));
    }
    assert(g_file_paths.count(m_file_path) == 0);
    g_file_paths.insert(m_file_path);
}

bool SQLiteDatabase::PrepareDirectory() const
{
    // Try to create the directory containing the wallet file and lock it
    TryCreateDirectories(m_dir_path);
    if (!LockDirectory(m_dir_path, ".walletlock")) {
        LogPrintf("Cannot obtain a lock on wallet directory %s. Another instance of bitcoin may be using it.\n", m_dir_path);
        return false;
    }
    return true;
}

void SQLiteDatabase::SetupSQLStatements()
{
    std::string read_sql = "SELECT value FROM main WHERE key = ?";
    std::string insert_sql = "INSERT INTO main VALUES(?, ?)";
    std::string overwrite_sql = "INSERT OR REPLACE INTO main VALUES(?, ?)";
    std::string delete_sql = "DELETE FROM main WHERE key = ?";
    std::string cursor_sql = "SELECT key, value FROM main";

    int res;
    if (!m_read_stmt) {
        if ((res = sqlite3_prepare_v2(m_db, read_sql.c_str(), -1, &m_read_stmt, nullptr)) != SQLITE_OK) {
            throw std::runtime_error(strprintf("SQLiteDatabase: Failed to setup SQL statements: %s\n", sqlite3_errstr(res)));
        }
    }
    if (!m_insert_stmt) {
        if ((res = sqlite3_prepare_v2(m_db, insert_sql.c_str(), -1, &m_insert_stmt, nullptr)) != SQLITE_OK) {
            throw std::runtime_error(strprintf("SQLiteDatabase: Failed to setup SQL statements: %s\n", sqlite3_errstr(res)));
        }
    }
    if (!m_overwrite_stmt) {
        if ((res = sqlite3_prepare_v2(m_db, overwrite_sql.c_str(), -1, &m_overwrite_stmt, nullptr)) != SQLITE_OK) {
            throw std::runtime_error(strprintf("SQLiteDatabase: Failed to setup SQL statements: %s\n", sqlite3_errstr(res)));
        }
    }
    if (!m_delete_stmt) {
        if ((res = sqlite3_prepare_v2(m_db, delete_sql.c_str(), -1, &m_delete_stmt, nullptr)) != SQLITE_OK) {
            throw std::runtime_error(strprintf("SQLiteDatabase: Failed to setup SQL statements: %s\n", sqlite3_errstr(res)));
        }
    }
    if (!m_cursor_stmt) {
        if ((res = sqlite3_prepare_v2(m_db, cursor_sql.c_str(), -1, &m_cursor_stmt, nullptr)) != SQLITE_OK) {
            throw std::runtime_error(strprintf("SQLiteDatabase: Failed to setup SQL statements : %s\n", sqlite3_errstr(res)));
        }
    }
}

SQLiteDatabase::~SQLiteDatabase()
{
    Close();
    LOCK(cs_sqlite);
    g_file_paths.erase(m_file_path);
    if (g_file_paths.empty()) {
        sqlite3_shutdown();
    }
}

void SQLiteDatabase::Open(const char* mode)
{
    if (!PrepareDirectory()) {
        throw std::runtime_error("Cannot obtain a lock on wallet directory");
    }

    m_read_only = (!strchr(mode, '+') && !strchr(mode, 'w'));
    if (m_dummy) return;

    bool create = strchr(mode, 'c') != nullptr;
    int flags = SQLITE_OPEN_NOFOLLOW; // Disallow symlink files
    if (m_read_only) {
        flags = SQLITE_OPEN_READONLY;
    } else {
        flags = SQLITE_OPEN_READWRITE;
    }
    if (create) {
        flags |= SQLITE_OPEN_CREATE;
    }
    if (m_mock) {
        flags = SQLITE_OPEN_MEMORY; // In memory database for mock db
    }

    if (m_db == nullptr) {
        sqlite3* db = nullptr;
        int ret = sqlite3_open_v2(m_file_path.c_str(), &db, flags, nullptr);
        if (ret != SQLITE_OK) {
            throw std::runtime_error(strprintf("SQLiteDatabase: Failed to open database: %s\n", sqlite3_errstr(ret)));
        }
        // TODO: Maybe(?) Check the file wasn't copied and a duplicate opened

        if (create) {
            bool table_exists;
            // Check that the main table exists
            sqlite3_stmt* check_main_stmt;
            std::string check_main = "SELECT name FROM sqlite_master WHERE type='table' AND name='main'";
            ret = sqlite3_prepare_v2(db, check_main.c_str(), -1, &check_main_stmt, nullptr);
            if (ret != SQLITE_OK) {
                throw std::runtime_error(strprintf("SQLiteDatabase: Failed to prepare statement to check table existence: %s\n", sqlite3_errstr(ret)));
            }
            ret = sqlite3_step(check_main_stmt);
            if (sqlite3_finalize(check_main_stmt) != SQLITE_OK) {
                throw std::runtime_error(strprintf("SQLiteDatabase: Failed to finalize statement checking table existence: %s\n", sqlite3_errstr(ret)));
            }
            if (ret == SQLITE_DONE) {
                table_exists = false;
            } else if (ret == SQLITE_ROW) {
                table_exists = true;
            } else {
                throw std::runtime_error(strprintf("SQLiteDatabase: Failed to execute statement to check table existence: %s\n", sqlite3_errstr(ret)));
            }

            if (!table_exists) {
                // Make the table for our key-value pairs
                std::string create_stmt = "CREATE TABLE main(key BLOB PRIMARY KEY, value BLOB)";
                ret = sqlite3_exec(db, create_stmt.c_str(), nullptr, nullptr, nullptr);
                if (ret != SQLITE_OK) {
                    throw std::runtime_error(strprintf("SQLiteDatabase: Failed to create new database: %s\n", sqlite3_errstr(ret)));
                }
            }
        }

        m_db = db;
    }
    SetupSQLStatements();
}

bool SQLiteDatabase::Rewrite(const char* skip)
{
    return false;
}

bool SQLiteDatabase::PeriodicFlush()
{
    return false;
}

bool SQLiteDatabase::Backup(const std::string& dest) const
{
    return false;
}

void SQLiteDatabase::Close()
{
    assert(m_refcount == 0);

    // Free all of the prepared statements
    sqlite3_finalize(m_read_stmt);
    sqlite3_finalize(m_insert_stmt);
    sqlite3_finalize(m_overwrite_stmt);
    sqlite3_finalize(m_delete_stmt);
    sqlite3_finalize(m_cursor_stmt);

    int res = sqlite3_close(m_db);
    if (res != SQLITE_OK) {
        throw std::runtime_error(strprintf("SQLiteDatabase: Failed to close database: %s\n", sqlite3_errstr(res)));
    }
    m_db = nullptr;

    UnlockDirectory(m_dir_path, ".walletlock");
}

void SQLiteDatabase::Flush()
{
}

void SQLiteDatabase::ReloadDbEnv()
{
}

void SQLiteDatabase::Release()
{
    m_refcount--;
}

void SQLiteDatabase::Acquire()
{
    m_refcount++;
}

bool SQLiteDatabase::DBRead(CDataStream& key, CDataStream& value) const
{
    if (!m_db) return false;

    // Bind: leftmost parameter in statement is index 1
    int res = sqlite3_bind_blob(m_read_stmt, 1, key.data(), key.size(), SQLITE_STATIC);
    if (res != SQLITE_OK) {
        sqlite3_clear_bindings(m_read_stmt);
        sqlite3_reset(m_read_stmt);
        return false;
    }
    res = sqlite3_step(m_read_stmt);
    if (res != SQLITE_ROW) {
        sqlite3_clear_bindings(m_read_stmt);
        sqlite3_reset(m_read_stmt);
        return false;
    }
    // Leftmost column in result is index 0
    const char* data = (const char*)sqlite3_column_blob(m_read_stmt, 0);
    int data_size = sqlite3_column_bytes(m_read_stmt, 0);
    value.write(data, data_size);

    sqlite3_clear_bindings(m_read_stmt);
    sqlite3_reset(m_read_stmt);
    return true;
}

bool SQLiteDatabase::DBWrite(CDataStream& key, CDataStream& value, bool overwrite) const
{
    if (!m_db) return false;
    if (m_read_only) assert(!"Write called on database in read-only mode");

    sqlite3_stmt* stmt;
    if (overwrite) {
        stmt = m_overwrite_stmt;
    } else {
        stmt = m_insert_stmt;
    }

    // Bind: leftmost parameter in statement is index 1
    // Insert index 1 is key, 2 is value
    int res = sqlite3_bind_blob(stmt, 1, key.data(), key.size(), SQLITE_STATIC);
    if (res != SQLITE_OK) {
        sqlite3_clear_bindings(stmt);
        sqlite3_reset(stmt);
        return false;
    }
    res = sqlite3_bind_blob(stmt, 2, value.data(), value.size(), SQLITE_STATIC);
    if (res != SQLITE_OK) {
        sqlite3_clear_bindings(stmt);
        sqlite3_reset(stmt);
        return false;
    }

    // Execute
    res = sqlite3_step(stmt);
    sqlite3_clear_bindings(stmt);
    sqlite3_reset(stmt);
    return res == SQLITE_DONE;
}

bool SQLiteDatabase::DBErase(CDataStream& key) const
{
    if (!m_db) return false;
    if (m_read_only) assert(!"Erase called on database in read-only mode");

    // Bind: leftmost parameter in statement is index 1
    int res = sqlite3_bind_blob(m_delete_stmt, 1, key.data(), key.size(), SQLITE_STATIC);
    if (res != SQLITE_OK) {
        sqlite3_clear_bindings(m_delete_stmt);
        sqlite3_reset(m_delete_stmt);
        return false;
    }

    // Execute
    res = sqlite3_step(m_delete_stmt);
    sqlite3_clear_bindings(m_delete_stmt);
    sqlite3_reset(m_delete_stmt);
    return res == SQLITE_DONE;
}

bool SQLiteDatabase::DBExists(CDataStream& key) const
{
    CDataStream value(SER_DISK, CLIENT_VERSION);
    return DBRead(key, value);
}

bool SQLiteDatabase::CreateCursor()
{
    if (!m_db) return false;
    return true;
}

bool SQLiteDatabase::ReadAtCursor(CDataStream& key, CDataStream& value, bool& complete)
{
    complete = false;

    int res = sqlite3_step(m_cursor_stmt);
    if (res == SQLITE_DONE) {
        complete = true;
        return true;
    } else if (res != SQLITE_ROW) {
        return false;
    }

    // Leftmost column in result is index 0
    const char* key_data = (const char*)sqlite3_column_blob(m_cursor_stmt, 0);
    int key_data_size = sqlite3_column_bytes(m_cursor_stmt, 0);
    key.write(key_data, key_data_size);
    const char* value_data = (const char*)sqlite3_column_blob(m_cursor_stmt, 1);
    int value_data_size = sqlite3_column_bytes(m_cursor_stmt, 1);
    value.write(value_data, value_data_size);
    return true;
}

void SQLiteDatabase::CloseCursor()
{
    sqlite3_reset(m_cursor_stmt);
}

bool SQLiteDatabase::TxnBegin()
{
    return false;
}

bool SQLiteDatabase::TxnCommit()
{
    return false;
}

bool SQLiteDatabase::TxnAbort()
{
    return false;
}

std::string SQLiteDatabaseVersion()
{
    return std::string(sqlite3_libversion());
}
