// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/migrate.h>

void BerkeleyRODatabase::Open()
{
}

std::unique_ptr<DatabaseBatch> BerkeleyRODatabase::MakeBatch(bool flush_on_close)
{
    return std::make_unique<BerkeleyROBatch>(*this);
}

bool BerkeleyRODatabase::Backup(const std::string& dest) const
{
    return false;
}

bool BerkeleyROBatch::ReadKey(CDataStream&& key, CDataStream& value)
{
    return false;
}

bool BerkeleyROBatch::HasKey(CDataStream&& key)
{
    return false;
}

bool BerkeleyROBatch::StartCursor()
{
    return false;
}

bool BerkeleyROBatch::ReadAtCursor(CDataStream& ssKey, CDataStream& ssValue, bool& complete)
{
    return false;
}

void BerkeleyROBatch::CloseCursor()
{
}
