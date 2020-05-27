// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_SQLITE_H
#define BITCOIN_WALLET_SQLITE_H

#include <wallet/db.h>

#include <atomic>

#include <sqlite3.h>

struct bilingual_str;

/** An instance of this class represents one SQLite3 database.
 **/
class SQLiteDatabase : public WalletDatabase
{
private:
    bool m_read_only = false;
    bool m_dummy = false;
    bool m_mock = false;

    sqlite3* m_db;

    const std::string m_file_path;
    const std::string m_dir_path;

    bool DBRead(CDataStream& key, CDataStream& value) const override;
    bool DBWrite(CDataStream& key, CDataStream& value, bool overwrite=true) const override;
    bool DBErase(CDataStream& key) const override;
    bool DBExists(CDataStream& key) const override;

    bool PrepareDirectory() const;

    sqlite3_stmt* m_read_stmt = nullptr;
    sqlite3_stmt* m_insert_stmt = nullptr;
    sqlite3_stmt* m_overwrite_stmt = nullptr;
    sqlite3_stmt* m_delete_stmt = nullptr;
    sqlite3_stmt* m_cursor_stmt = nullptr;

    void SetupSQLStatements();

public:
    /** Create dummy DB handle */
    SQLiteDatabase() : WalletDatabase(), m_dummy(true), m_db(nullptr)
    {
    }

    /** Create DB handle to real database */
    SQLiteDatabase(const fs::path& dir_path, const fs::path& file_path, bool mock=false);

    ~SQLiteDatabase();

    /** Open the database if it is not already opened */
    void Open(const char* mode) override;

    /** Close the database */
    void Close() override;

    std::string GetFilePath() const override;

    /** Indicate the a new database user has began using the database. Increments m_refcount */
    void Acquire() override;
    /** Indicate that database user has stopped using the database. Decrement m_refcount */
    void Release() override;

    /** Rewrite the entire database on disk, with the exception of key pszSkip if non-zero
     */
    bool Rewrite(const char* skip=nullptr) override;

    /** Back up the entire database to a file.
     */
    bool Backup(const std::string& dest) const override;

    /** Make sure all changes are flushed to disk.
     */
    void Flush() override;
    /* flush the wallet passively (TRY_LOCK)
       ideal to be called periodically */
    bool PeriodicFlush() override;

    void ReloadDbEnv() override;

    /* verifies the environment and database file */
    bool Verify(bilingual_str& error) override;

    bool CreateCursor() override;
    bool ReadAtCursor(CDataStream& ssKey, CDataStream& ssValue, bool& complete) override;
    void CloseCursor() override;

    bool TxnBegin() override;
    bool TxnCommit() override;
    bool TxnAbort() override;
};

std::string SQLiteDatabaseVersion();
bool IsSQLiteWalletLoaded(const fs::path& wallet_path);

#endif // BITCOIN_WALLET_SQLITE_H
