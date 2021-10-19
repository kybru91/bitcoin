// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/migrate.h>

#include <crypto/common.h> // For ReadBE32
#include <logging.h>
#include <streams.h>
#include <uint256.h>

#include <optional>
#include <variant>

// Magic bytes in both endianness's
constexpr uint32_t BTREE_MAGIC = 0x00053162; // If the file endianness matches our system, we see this magic
constexpr uint32_t BTREE_MAGIC_OE = 0x62310500; // If the file endianness is the other one, we will see this magic

constexpr uint32_t PAGENUM_INVALID = 0;       // Invalid page number in any database
constexpr uint32_t PAGENUM_BASE_METADATA = 0; // Base database: metadata page number

enum class PageType : uint8_t
{
    INVALID = 0,         // Invalid page type
    DUPLICATE = 1,       // Duplicate. Deprecated and no longer used
    HASH_UNSORTED = 2,   // Hash pages. Deprecated.
    BTREE_INTERNAL = 3,  // BTree internal
    RECNO_INTERNAL = 4,  // Recno internal
    BTREE_LEAF = 5,      // BTree leaf
    RECNO_LEAF = 6,      // Recno leaf
    OVERFLOW = 7,        // Overflow
    HASH_META = 8,       // Hash metadata
    BTREE_META = 9,      // BTree metadata
    QUEUE_META = 10,     // Queue Metadata
    QUEUE_DATA = 11,     // Queue Data
    DUPLICATE_LEAF = 12, // Off-page duplicate leaf
    HASH_SORTED = 13,    // Sorted hash page

    PAGETYPE_MAX = 14,
};

enum class RecordType : uint8_t
{
    KEYDATA = 1,
    DUPLICATE = 2,
    OVERFLOW = 3,
    DELETE = 0x80, // Indicate this record is deleted. This is AND'd with the real type.
};

enum class BTreeFlags : uint32_t
{
    DUP = 1,         // Duplicates
    RECNO = 2,       // Recno tree
    RECNUM = 4,      // BTree: Maintain record counts
    FIXEDLEN = 8,    // Recno: fixed length records
    RENUMBER = 0x10, // Recno: renumber on insert/delete
    SUBDB = 0x20,    // Subdatabases
    DUPSORT = 0x40,  // Duplicates are sorted
    COMPRESS = 0x80, // Compressed
};

/** Berkeley DB BTree metadata page layout */
class MetaPage
{
public:
    uint64_t lsn;             // Log Sequence Number
    uint32_t page_num;        // Current page number
    uint32_t magic;           // Magic number
    uint32_t version;         // Version
    uint32_t pagesize;        // Page size
    uint8_t encrypt_algo;     // Encryption algorithm
    PageType type;            // Page type
    uint8_t metaflags;        // Meta-only flags
    uint8_t unused1;          // Unused
    uint32_t free_list;       // Free list page number
    uint32_t last_page;       // Page number of last page in db
    uint32_t partitions;      // Number of partitions
    uint32_t key_count;       // Cached key count
    uint32_t record_count;    // Cached record count
    BTreeFlags flags;         // Flags
    uint160 uid;              // Unique file ID (20 bytes, fits in uint16)
    uint32_t unused2;         // Unused
    uint32_t minkey;          // Minimum key
    uint32_t re_len;          // Recno: fixed length record length
    uint32_t re_pad;          // Recno: fixed length record pad
    uint32_t root;            // Root page number
    char unused3[368];        // 92 * 4 bytes of unused space
    uint32_t crypto_magic;    // Crypto magic n  umber
    char trash[12];           // 3 * 4 bytes of trash space
    unsigned char iv[20];     // Crypto IV
    unsigned char chksum[16]; // Checksum

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        s >> lsn;
        s >> page_num;
        s >> magic;
        s >> version;
        s >> pagesize;
        s >> encrypt_algo;

        uint8_t uint8_type;
        s >> uint8_type;
        type = static_cast<PageType>(uint8_type);

        s >> metaflags;
        s >> unused1;
        s >> free_list;
        s >> last_page;
        s >> partitions;
        s >> key_count;
        s >> record_count;

        uint32_t uint32_flags;
        s >> uint32_flags;
        flags = static_cast<BTreeFlags>(uint32_flags);

        s >> uid;
        s >> unused2;
        s >> minkey;
        s >> re_len;
        s >> re_pad;
        s >> root;
        s >> unused3;
        s >> crypto_magic;
        s >> trash;
        s >> iv;
        s >> chksum;
    }
};

/** General class for records in a BDB BTree database. Contains common fields. */
class RecordHeader
{
public:
    uint16_t len;  // Key/data item length
    RecordType type;  // Page type and DELETE FLAG

    static constexpr size_t SIZE = 3; // The record header is 3 bytes

    RecordType GetRealType() const
    {
        return static_cast<RecordType>(static_cast<uint8_t>(type) & ~static_cast<uint8_t>(RecordType::DELETE));
    }

    bool IsDeleted() const
    {
        return static_cast<uint8_t>(type) & static_cast<uint8_t>(RecordType::DELETE);
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        s >> len;

        uint8_t uint8_type;
        s >> uint8_type;
        type = static_cast<RecordType>(uint8_type);
    }
};

/** Class for data in the record directly */
class DataRecord
{
public:
    DataRecord(const RecordHeader& header) : m_header(header) {}
    DataRecord() = delete;

    RecordHeader m_header;

    std::vector<unsigned char> data; // Variable length key/data item

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        data.resize(m_header.len);
        s.read(reinterpret_cast<char*>(data.data()), m_header.len);
    }
};

/** Class for records representing internal nodes of the BTree. */
class InternalRecord
{
public:
    InternalRecord(const RecordHeader& header) : m_header(header) {}
    InternalRecord() = delete;

    RecordHeader m_header;

    uint8_t unused;                   // Padding, unused
    uint32_t page_num;                // Page number of referenced page
    uint32_t records;                 // Subtree record count
    std::vector<unsigned char> data;  // Variable length key item

    static constexpr size_t FIXED_SIZE = 9; // Size of fixed data is 9 bytes

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        s >> unused;
        s >> page_num;
        s >> records;

        data.resize(m_header.len);
        s.read(reinterpret_cast<char*>(data.data()), m_header.len);
    }
};

/** Class for records representing overflow records of the BTree.
 * Overflow records point to a page which contains the data in the record.
 * Those pages may point to further pages with the rest of the data if it does not fit
 * in one page */
class OverflowRecord
{
public:
    OverflowRecord(const RecordHeader& header) : m_header(header) {}
    OverflowRecord() = delete;

    RecordHeader m_header;

    uint8_t unused2;      // Padding, unused
    uint32_t page_number; // Page number where data begins
    uint32_t item_len;    // Total length of item

    static constexpr size_t SIZE = 9; // Overflow record is always 9 bytes

    std::vector<unsigned char> data; // Data from all of the overflow pages

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        s >> unused2;
        s >> page_number;
        s >> item_len;
    }
};

/** A generic data page in the database. Contains fields common to all data pages. */
class PageHeader
{
public:
    uint64_t lsn;       // Log Sequence Number
    uint32_t page_num;  // Current page number
    uint32_t prev_page; // Previous page number
    uint32_t next_page; // Next page number
    uint16_t entries;   // Number of items on the page
    uint16_t hf_offset; // High free byte page offset
    uint8_t level;      // Btree page level
    PageType type;      // Page type

    static constexpr size_t SIZE = 26; // The header is 26 bytes

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        s >> lsn;
        s >> page_num;
        s >> prev_page;
        s >> next_page;
        s >> entries;
        s >> hf_offset;
        s >> level;

        uint8_t uint8_type;
        s >> uint8_type;
        type = static_cast<PageType>(uint8_type);
    }
};

/** A page of records in the database */
class RecordsPage
{
public:
    RecordsPage(const PageHeader& header) : m_header(header) {}
    RecordsPage() = delete;

    PageHeader m_header;

    std::vector<uint16_t> indexes;
    std::vector<std::variant<DataRecord, OverflowRecord>> records;

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        // Current position within the page
        size_t pos = PageHeader::SIZE;

        // Get the items
        for (uint32_t i = 0; i < m_header.entries; ++i) {
            // Get the index
            uint16_t index;
            s >> index;
            indexes.push_back(index);
            pos += sizeof(uint16_t);

            // Go to the offset from the index
            size_t to_jump = index - pos;
            s.ignore(to_jump);

            // Read the record
            RecordHeader rec_hdr;
            s >> rec_hdr;
            to_jump += RecordHeader::SIZE;

            switch (rec_hdr.GetRealType()) {
            case RecordType::KEYDATA:
            {
                DataRecord record(rec_hdr);
                s >> record;
                records.push_back(record);
                to_jump += rec_hdr.len;
                break;
            }
            case RecordType::DUPLICATE:
            case RecordType::OVERFLOW:
            {
                OverflowRecord record(rec_hdr);
                s >> record;
                records.push_back(record);
                to_jump += OverflowRecord::SIZE;
                break;
            }
            default:
                assert(false);
            }

            // Go back to the indexes
            s.seek(-to_jump, SEEK_CUR);
        }
    }
};

/** A page containing overflow data */
class OverflowPage
{
public:
    OverflowPage(const PageHeader& header) : m_header(header) {}
    OverflowPage() = delete;

    PageHeader m_header;

    // BDB overloads some page fields to store overflow page data
    // hf_offset contains the length of the overflow data stored on this page
    // entries contains a reference count for references to this item
    
    // The overflow data itself. Begins immediately following header
    std::vector<unsigned char> data;

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        data.resize(m_header.hf_offset);
        s.read(reinterpret_cast<char*>(data.data()), m_header.hf_offset);
    }
};

/** A page of records in the database */
class InternalPage
{
public:
    InternalPage(const PageHeader& header) : m_header(header) {}
    InternalPage() = delete;

    PageHeader m_header;

    std::vector<uint16_t> indexes;
    std::vector<InternalRecord> records;

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        // Current position within the page
        size_t pos = PageHeader::SIZE;

        // Get the items
        for (uint32_t i = 0; i < m_header.entries; ++i) {
            // Get the index
            uint16_t index;
            s >> index;
            indexes.push_back(index);
            pos += sizeof(uint16_t);

            // Go to the offset from the index
            size_t to_jump = index - pos;
            s.ignore(to_jump);

            // Read the record
            RecordHeader rec_hdr;
            s >> rec_hdr;
            to_jump += RecordHeader::SIZE;

            assert(rec_hdr.GetRealType() == RecordType::KEYDATA);
            InternalRecord record(rec_hdr);
            s >> record;
            records.push_back(record);
            to_jump += InternalRecord::FIXED_SIZE + rec_hdr.len;

            // Go back to the indexes
            s.seek(-to_jump, SEEK_CUR);

        }
    }
};

static std::optional<MetaPage> ReadMetaPage(CAutoFile& f)
{
    // Read the metapage
    MetaPage meta;
    f >> meta;

    // Sanity checks
    if (meta.magic != BTREE_MAGIC && meta.magic != BTREE_MAGIC_OE) {
        throw std::runtime_error("Not a BDB file");
    }
    if (meta.magic == BTREE_MAGIC_OE) {
        // TODO: Flip the endinaness of things
    }
    if (meta.version != 9) {
        throw std::runtime_error("Unsupported BDB data file version number");
    }
    if (meta.type != PageType::BTREE_META) {
        throw std::runtime_error("Unexpected page type, should be 9 (BTree Metadata)");
    }
    if (meta.flags != BTreeFlags::SUBDB) {
        throw std::runtime_error("Unexpected database flags, should only be 0x20 (subdatabases)");
    }

    return meta;
}

static void SeekToPage(CAutoFile& s, uint32_t page_num, uint32_t page_size)
{
    size_t pos = page_num * page_size;
    s.seek(pos, SEEK_SET);
}

void BerkeleyRODatabase::Open()
{
    // Open the file
    FILE *file = fsbridge::fopen(m_filepath, "r");
    CAutoFile db_file(file, 0, 0);
    if (db_file.IsNull()) {
        db_file.fclose();
        throw std::runtime_error("BerkeleyRODatabase: Failed to open database file");
    }

    uint32_t page_size = 4096; // Default page size

    // Read the outer metapage
    std::optional<MetaPage> outer_meta = ReadMetaPage(db_file);
    page_size = outer_meta->pagesize;

    // Read the root page
    SeekToPage(db_file, outer_meta->root, page_size);
    PageHeader header;
    db_file >> header;
    if (header.type != PageType::BTREE_LEAF) {
        throw std::runtime_error("Unexpected outer database root page type");
    }
    if (header.entries != 2) {
        throw std::runtime_error("Unexpected number of entries in outer database root page");
    }
    RecordsPage page(header);
    db_file >> page;

    // First record should be the string "main"
    assert(std::holds_alternative<DataRecord>(page.records.at(0)));
    if (std::get_if<DataRecord>(&page.records.at(0))->data != std::vector<unsigned char>({'m', 'a', 'i', 'n'})) {
        throw std::runtime_error("Subdatabase has an unexpected name");
    }
    assert(std::holds_alternative<DataRecord>(page.records.at(1)));
    if (std::get_if<DataRecord>(&page.records.at(1))->m_header.len != 4) {
        throw std::runtime_error("Subdatabase page number has unexpected length");
    }

    // Read subdatabase page number
    // It is written as a big endian 32 bit number
    uint32_t main_db_page = ReadBE32(std::get_if<DataRecord>(&page.records.at(1))->data.data());

    // Read the inner metapage
    SeekToPage(db_file, main_db_page, page_size);
    std::optional<MetaPage> inner_meta = ReadMetaPage(db_file);
    assert(inner_meta->pagesize == page_size);

    // Do a DFS through the BTree, starting at root
    std::vector<uint32_t> pages{inner_meta->root};
    while (pages.size() > 0) {
        uint32_t curr_page = pages.back();
        pages.pop_back();
        SeekToPage(db_file, curr_page, page_size);
        PageHeader header;
        db_file >> header;
        if (header.type != PageType::BTREE_LEAF && header.type != PageType::BTREE_INTERNAL) {
            throw std::runtime_error("Unexpected inner database page type");
        }
        switch (header.type) {
        case PageType::BTREE_INTERNAL:
        {
            InternalPage int_page(header);
            db_file >> int_page;
            for (const InternalRecord& rec : int_page.records) {
                if (rec.m_header.IsDeleted()) continue;
                pages.push_back(rec.page_num);
            }
            break;
        }
        case PageType::BTREE_LEAF:
        {
            RecordsPage rec_page(header);
            db_file >> rec_page;
            bool is_key = true;
            std::vector<unsigned char> key;
            for (const std::variant<DataRecord, OverflowRecord>& rec : rec_page.records) {
                std::vector<unsigned char> data;
                if (const DataRecord* drec = std::get_if<DataRecord>(&rec)) {
                    if (drec->m_header.IsDeleted()) continue;
                    data = drec->data;
                } else if (const OverflowRecord* orec = std::get_if<OverflowRecord>(&rec)) {
                    if (orec->m_header.IsDeleted()) continue;
                    uint32_t next_page = orec->page_number;
                    while (next_page != 0) {
                        SeekToPage(db_file, next_page, page_size);
                        PageHeader opage_header;
                        db_file >> opage_header;
                        OverflowPage opage(opage_header);
                        db_file >> opage;
                        data.insert(data.end(), opage.data.begin(), opage.data.end());
                        next_page = opage_header.next_page;
                    }
                } else {
                    assert(false);
                }

                if (is_key) {
                    key = data;
                } else {
                    m_records.emplace(key, data);
                    key.clear();
                }
                is_key = !is_key;
            }
            break;
        }
        default:
            assert(false);
        }
    }
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

std::unique_ptr<BerkeleyRODatabase> MakeBerkeleyRODatabase(const fs::path& path, const DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error)
{
    fs::path data_file = BDBDataFile(path);
    std::unique_ptr<BerkeleyRODatabase> db = std::make_unique<BerkeleyRODatabase>(data_file);
    status = DatabaseStatus::SUCCESS;
    return db;
}
