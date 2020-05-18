// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/sqlite.h>

#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/db.h>

#include <stdint.h>

bool IsSQLiteWalletLoaded(const fs::path& wallet_path)
{
    return false;
}

bool SQLiteDatabase::Verify(bilingual_str& error)
{
    return false;
}

SQLiteDatabase::~SQLiteDatabase()
{
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
