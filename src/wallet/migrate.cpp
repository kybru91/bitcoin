// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/migrate.h>

#include <logging.h>

void BerkeleyRODatabase::Open()
{
}

std::unique_ptr<DatabaseBatch> BerkeleyRODatabase::MakeBatch(bool flush_on_close)
{
    return std::make_unique<BerkeleyROBatch>(*this);
}

bool BerkeleyRODatabase::Backup(const std::string& dest) const
{
    fs::path src(m_filepath);
    fs::path dst(fs::PathFromString(dest));

    if (fs::is_directory(dst)) {
        dst = BDBDataFile(dst);
    }
    try {
        if (fs::equivalent(src, dst)) {
            LogPrintf("cannot backup to wallet source file %s\n", fs::PathToString(dst));
            return false;
        }

        fs::copy_file(src, dst, fs::copy_option::overwrite_if_exists);
        LogPrintf("copied %s to %s\n", fs::PathToString(m_filepath), fs::PathToString(dst));
        return true;
    } catch (const fs::filesystem_error& e) {
        LogPrintf("error copying %s to %s - %s\n", fs::PathToString(m_filepath), fs::PathToString(dst), fsbridge::get_filesystem_error_message(e));
        return false;
    }
}

bool BerkeleyROBatch::ReadKey(CDataStream&& key, CDataStream& value)
{
    std::vector<unsigned char> vkey(key.begin(), key.end());
    if (m_database.m_records.count(vkey) == 0) {
        return false;
    }
    auto val = m_database.m_records.at(vkey);
    value.clear();
    value.insert(value.begin(), val.begin(), val.end());
    return true;
}

bool BerkeleyROBatch::HasKey(CDataStream&& key)
{
    std::vector<unsigned char> vkey(key.begin(), key.end());
    return m_database.m_records.count(vkey) > 0;
}

bool BerkeleyROBatch::StartCursor()
{
    assert(m_cursor == std::nullopt);
    m_cursor.emplace(m_database.m_records.begin());
    return true;
}

bool BerkeleyROBatch::ReadAtCursor(CDataStream& ssKey, CDataStream& ssValue, bool& complete)
{
    if (m_cursor == std::nullopt) {
        return false;
    }
    assert(m_cursor != std::nullopt);
    complete = false;
    ssKey.insert(ssKey.begin(), (*m_cursor)->first.begin(), (*m_cursor)->first.end());
    ssValue.insert(ssValue.begin(), (*m_cursor)->second.begin(), (*m_cursor)->second.end());
    (*m_cursor)++;
    if (m_cursor == m_database.m_records.end()) {
        complete = true;
        m_cursor.reset();
    }
    return true;
}

void BerkeleyROBatch::CloseCursor()
{
    m_cursor.reset();
}
