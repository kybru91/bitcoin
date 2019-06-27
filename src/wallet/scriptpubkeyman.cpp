// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/scriptpubkeyman.h>

bool LegacyScriptPubKeyMan::GetNewDestination(const OutputType type, CTxDestination& dest, std::string& error)
{
    return false;
}

isminetype LegacyScriptPubKeyMan::IsMine(const CScript& script) const
{
    return ISMINE_NO;
}

bool LegacyScriptPubKeyMan::IsCrypted() const
{
    return fUseCrypto;
}

bool LegacyScriptPubKeyMan::SetCrypted()
{
    LOCK(cs_KeyStore);
    if (fUseCrypto)
        return true;
    if (!mapKeys.empty())
        return false;
    fUseCrypto = true;
    return true;
}

bool LegacyScriptPubKeyMan::IsLocked() const
{
    if (!IsCrypted()) {
        return false;
    }
    LOCK(cs_KeyStore);
    return vMasterKey.empty();
}

bool LegacyScriptPubKeyMan::Lock()
{
    if (!SetCrypted())
        return false;

    {
        LOCK(cs_KeyStore);
        vMasterKey.clear();
    }

    return true;
}

bool LegacyScriptPubKeyMan::Unlock(const CKeyingMaterial& vMasterKeyIn, bool accept_no_keys)
{
    {
        LOCK(cs_KeyStore);
        if (!SetCrypted())
            return false;

        bool keyPass = mapCryptedKeys.empty(); // Always pass when there are no encrypted keys
        bool keyFail = false;
        CryptedKeyMap::const_iterator mi = mapCryptedKeys.begin();
        for (; mi != mapCryptedKeys.end(); ++mi)
        {
            const CPubKey &vchPubKey = (*mi).second.first;
            const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
            CKey key;
            if (!DecryptKey(vMasterKeyIn, vchCryptedSecret, vchPubKey, key))
            {
                keyFail = true;
                break;
            }
            keyPass = true;
            if (fDecryptionThoroughlyChecked)
                break;
        }
        if (keyPass && keyFail)
        {
            LogPrintf("The wallet is probably corrupted: Some keys decrypt but not all.\n");
            throw std::runtime_error("Error unlocking wallet: some keys decrypt but not all. Your wallet file may be corrupt.");
        }
        if (keyFail || (!keyPass && !accept_no_keys))
            return false;
        vMasterKey = vMasterKeyIn;
        fDecryptionThoroughlyChecked = true;
    }
    return true;
}

bool LegacyScriptPubKeyMan::Encrypt(CKeyingMaterial& vMasterKeyIn, WalletBatch* batch)
{
    LOCK(cs_KeyStore);
    encrypted_batch = batch;
    if (!mapCryptedKeys.empty() || IsCrypted()) {
        encrypted_batch = nullptr;
        return false;
    }

    fUseCrypto = true;
    for (const KeyMap::value_type& mKey : mapKeys)
    {
        const CKey &key = mKey.second;
        CPubKey vchPubKey = key.GetPubKey();
        CKeyingMaterial vchSecret(key.begin(), key.end());
        std::vector<unsigned char> vchCryptedSecret;
        if (!EncryptSecret(vMasterKeyIn, vchSecret, vchPubKey.GetHash(), vchCryptedSecret)) {
            encrypted_batch = nullptr;
            return false;
        }
        if (!AddCryptedKey(vchPubKey, vchCryptedSecret)) {
            encrypted_batch = nullptr;
            return false;
        }
    }
    mapKeys.clear();
    encrypted_batch = nullptr;
    return true;
}

bool LegacyScriptPubKeyMan::GetReservedDestination(const OutputType type, bool internal, CTxDestination& address, int64_t& index, CKeyPool& keypool)
{
    return false;
}

void LegacyScriptPubKeyMan::KeepDestination(int64_t index)
{
}

void LegacyScriptPubKeyMan::ReturnDestination(int64_t index, bool internal, const CTxDestination& addr)
{
}

bool LegacyScriptPubKeyMan::TopUp(unsigned int size)
{
    return false;
}

void LegacyScriptPubKeyMan::MarkUnusedAddresses(const CScript& script)
{
}

void LegacyScriptPubKeyMan::UpgradeKeyMetadata()
{
}

bool LegacyScriptPubKeyMan::SetupGeneration(bool force)
{
    return false;
}

bool LegacyScriptPubKeyMan::IsHDEnabled() const
{
    return false;
}

bool LegacyScriptPubKeyMan::CanGetAddresses(bool internal)
{
    return false;
}

bool LegacyScriptPubKeyMan::Upgrade(int prev_version, int new_version, std::string& error)
{
    return false;
}

bool LegacyScriptPubKeyMan::HavePrivateKeys() const
{
    return false;
}

int64_t LegacyScriptPubKeyMan::GetOldestKeyPoolTime()
{
    return GetTime();
}

size_t LegacyScriptPubKeyMan::KeypoolCountExternalKeys()
{
    return 0;
}

unsigned int LegacyScriptPubKeyMan::GetKeypoolSize() const
{
    return 0;
}

int64_t LegacyScriptPubKeyMan::GetTimeFirstKey() const
{
    LOCK(cs_KeyStore);
    return nTimeFirstKey;
}

std::unique_ptr<SigningProvider> LegacyScriptPubKeyMan::GetSigningProvider(const CScript& script) const
{
    return MakeUnique<LegacySigningProvider>(this);
}

bool LegacyScriptPubKeyMan::CanProvide(const CScript& script, SignatureData& sigdata)
{
    return false;
}

const CKeyMetadata* LegacyScriptPubKeyMan::GetMetadata(uint160 id) const
{
    LOCK(cs_KeyStore);
    auto it = mapKeyMetadata.find(CKeyID(id));
    if (it != mapKeyMetadata.end()) {
        return &it->second;
    } else {
        auto it2 = m_script_metadata.find(CScriptID(id));
        if (it2 != m_script_metadata.end()) {
            return &it2->second;
        }
    }
    return nullptr;
}

uint256 LegacyScriptPubKeyMan::GetID() const
{
    return uint256S("0000000000000000000000000000000000000000000000000000000000000001");
}

bool LegacyScriptPubKeyMan::LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    return AddCryptedKeyInner(vchPubKey, vchCryptedSecret);
}

bool LegacyScriptPubKeyMan::AddCryptedKeyInner(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    LOCK(cs_KeyStore);
    if (!SetCrypted()) {
        return false;
    }

    mapCryptedKeys[vchPubKey.GetID()] = make_pair(vchPubKey, vchCryptedSecret);
    ImplicitlyLearnRelatedKeyScripts(vchPubKey);
    return true;
}

bool LegacyScriptPubKeyMan::AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    if (!AddCryptedKeyInner(vchPubKey, vchCryptedSecret))
        return false;
    {
        LOCK(cs_KeyStore);
        if (encrypted_batch)
            return encrypted_batch->WriteCryptedKey(vchPubKey,
                                                        vchCryptedSecret,
                                                        mapKeyMetadata[vchPubKey.GetID()]);
        else
            return WalletBatch(*m_database).WriteCryptedKey(vchPubKey,
                                                            vchCryptedSecret,
                                                            mapKeyMetadata[vchPubKey.GetID()]);
    }
}

/**
 * Update wallet first key creation time. This should be called whenever keys
 * are added to the wallet, with the oldest key creation time.
 */
void LegacyScriptPubKeyMan::UpdateTimeFirstKey(int64_t nCreateTime)
{
    LOCK(cs_KeyStore);
    if (nCreateTime <= 1) {
        // Cannot determine birthday information, so set the wallet birthday to
        // the beginning of time.
        nTimeFirstKey = 1;
    } else if (!nTimeFirstKey || nCreateTime < nTimeFirstKey) {
        nTimeFirstKey = nCreateTime;
    }
}

// Temp functions, remove later
std::map<CKeyID, std::pair<CPubKey, std::vector<unsigned char>>>& LegacyScriptPubKeyMan::GetMapCryptedKeys()
{
    LOCK(cs_KeyStore);
    return mapCryptedKeys;
}

std::map<CKeyID, CKey>& LegacyScriptPubKeyMan::GetMapKeys()
{
    LOCK(cs_KeyStore);
    return mapKeys;
}

void LegacyScriptPubKeyMan::SetEncryptedBatch(WalletBatch* batch)
{
    LOCK(cs_KeyStore);
    encrypted_batch = batch;
}

void LegacyScriptPubKeyMan::UnsetEncryptedBatch()
{
    LOCK(cs_KeyStore);
    encrypted_batch = nullptr;
}

void LegacyScriptPubKeyMan::AddKeyMeta(CKeyID id, const CKeyMetadata& meta)
{
    LOCK(cs_KeyStore);
    mapKeyMetadata[id] = meta;
}
