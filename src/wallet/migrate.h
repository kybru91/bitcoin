// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_MIGRATE_H
#define BITCOIN_WALLET_MIGRATE_H

#include <wallet/db.h>

#include <optional>

/**
 * A class representing a BerkeleyDB file from which we can only read records.
 * This is used only for migration of legacy to descriptor wallets
 */
class BerkeleyRODatabase : public WalletDatabase
{
private:
    const fs::path m_filepath;

public:
    /** Create dummy DB handle */
    BerkeleyRODatabase(const fs::path& filepath) : WalletDatabase(), m_filepath(filepath)
    {
        Open();
    }
    ~BerkeleyRODatabase() {};

    std::map<std::vector<unsigned char>, std::vector<unsigned char>> m_records;

    /** Open the database if it is not already opened. */
    void Open() override;

    /** Indicate the a new database user has began using the database. Increments m_refcount */
    void AddRef() override {}
    /** Indicate that database user has stopped using the database and that it could be flushed or closed. Decrement m_refcount */
    void RemoveRef() override {}

    /** Rewrite the entire database on disk, with the exception of key pszSkip if non-zero
     */
    bool Rewrite(const char* pszSkip=nullptr) override { return false; }

    /** Back up the entire database to a file.
     */
    bool Backup(const std::string& strDest) const override;

    /** Make sure all changes are flushed to database file.
     */
     void Flush() override {}
    /** Flush to the database file and close the database.
     *  Also close the environment if no other databases are open in it.
     */
    void Close() override {}
    /* flush the wallet passively (TRY_LOCK)
       ideal to be called periodically */
    bool PeriodicFlush() override { return false; }

    void IncrementUpdateCounter() override {}

    void ReloadDbEnv() override {}

    /** Return path to main database file for logs and error messages. */
    std::string Filename() override { return fs::PathToString(m_filepath); }

    std::string Format() override { return "bdb_ro"; }

    /** Make a DatabaseBatch connected to this database */
    std::unique_ptr<DatabaseBatch> MakeBatch(bool flush_on_close = true) override;
};

/** RAII class that provides access to a BerkeleyRODatabase */
class BerkeleyROBatch : public DatabaseBatch
{
private:
    const BerkeleyRODatabase& m_database;
    std::optional<std::map<std::vector<unsigned char>, std::vector<unsigned char>>::const_iterator> m_cursor{};

    bool ReadKey(CDataStream&& key, CDataStream& value) override;
    bool WriteKey(CDataStream&& key, CDataStream&& value, bool overwrite=true) override { return true; }
    bool EraseKey(CDataStream&& key) override { return false; }
    bool HasKey(CDataStream&& key) override;

public:
    explicit BerkeleyROBatch(const BerkeleyRODatabase& database) : m_database(database) {}
    ~BerkeleyROBatch() {}

    BerkeleyROBatch(const BerkeleyROBatch&) = delete;
    BerkeleyROBatch& operator=(const BerkeleyROBatch&) = delete;

    void Flush() override {}
    void Close() override {}

    bool StartCursor() override;
    bool ReadAtCursor(CDataStream& ssKey, CDataStream& ssValue, bool& complete) override;
    void CloseCursor() override;
    bool TxnBegin() override { return false; }
    bool TxnCommit() override { return false; }
    bool TxnAbort() override { return false; }
};

#endif // BITCOIN_WALLET_MIGRATE_H
