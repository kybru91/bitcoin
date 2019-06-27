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
    return false;
}

bool LegacyScriptPubKeyMan::Unlock(const CKeyingMaterial& vMasterKeyIn, bool accept_no_keys)
{
    return false;
}

bool LegacyScriptPubKeyMan::Encrypt(CKeyingMaterial& vMasterKeyIn, WalletBatch* batch)
{
    return false;
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
    return 0;
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

// Temp functions, remove later
void LegacyScriptPubKeyMan::SetEncKey(const CKeyingMaterial& master_key)
{
    vMasterKey = master_key;
}

void LegacyScriptPubKeyMan::ClearEncKey()
{
    vMasterKey.clear();
}

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
