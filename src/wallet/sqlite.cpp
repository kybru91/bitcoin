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
    return false;
}

bool SQLiteDatabase::Verify(bilingual_str& error)
{
    return false;
}

SQLiteDatabase::SQLiteDatabase(const fs::path& dir_path, const fs::path& file_path, bool mock) :
    WalletDatabase(), m_mock(mock), m_db(nullptr), m_file_path(file_path.string()), m_dir_path(dir_path.string())
{
    LogPrintf("Using SQLite Version %s\n", SQLiteDatabaseVersion());
    LogPrintf("Using wallet %s\n", m_dir_path);

    LOCK(cs_sqlite);
    assert(g_file_paths.count(m_file_path) == 0);
    g_file_paths.insert(m_file_path);
}

SQLiteDatabase::~SQLiteDatabase()
{
    Close();
    LOCK(cs_sqlite);
    g_file_paths.erase(m_file_path);
}

void SQLiteDatabase::Open(const char* pszMode)
{
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
}

void SQLiteDatabase::Flush()
{
}

void SQLiteDatabase::ReloadDbEnv()
{
}

void SQLiteDatabase::Release()
{
}

void SQLiteDatabase::Acquire()
{
}

bool SQLiteDatabase::DBRead(CDataStream& key, CDataStream& value) const
{
    return false;
}

bool SQLiteDatabase::DBWrite(CDataStream& key, CDataStream& value, bool overwrite) const
{
    return false;
}

bool SQLiteDatabase::DBErase(CDataStream& key) const
{
    return false;
}

bool SQLiteDatabase::DBExists(CDataStream& key) const
{
    return false;
}

bool SQLiteDatabase::CreateCursor()
{
    return false;
}

bool SQLiteDatabase::ReadAtCursor(CDataStream& key, CDataStream& value, bool& complete)
{
    return false;
}

void SQLiteDatabase::CloseCursor()
{
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
