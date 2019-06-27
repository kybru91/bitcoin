// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_SCRIPTPUBKEYMAN_H
#define BITCOIN_WALLET_SCRIPTPUBKEYMAN_H

#include <script/signingprovider.h>
#include <script/standard.h>
#include <wallet/crypter.h>
#include <wallet/ismine.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>

#include <functional>

#include <boost/signals2/signal.hpp>

enum class OutputType;

typedef std::function<void(WalletBatch&, uint64_t)> FlagFuncWithDB;
typedef std::function<bool(uint64_t)> FlagSetFunc;
typedef std::function<bool(enum WalletFeature)> VersionFunc;
typedef std::function<std::string()> NameFunc;
typedef std::function<void(enum WalletFeature, WalletBatch*, bool)> SetVersionFunc;

class ScriptPubKeyMan
{
protected:

    FlagSetFunc IsWalletFlagSet; // Function pointer to function that determines if a wallet flag is set
    FlagFuncWithDB UnsetWalletFlagWithDB; // Function pointer to function to unset wallet flags
    NameFunc GetDisplayName; // Function pointer to GetDisplayName to get the name of a wallet for WalletLogPrintf

    /** Internal database handle. */
    std::shared_ptr<WalletDatabase> m_database;

public:
    ScriptPubKeyMan(FlagSetFunc is_set_func, FlagFuncWithDB unset_flag_func, NameFunc wallet_name_func, std::shared_ptr<WalletDatabase> database)
        :   IsWalletFlagSet(is_set_func),
            UnsetWalletFlagWithDB(unset_flag_func),
            GetDisplayName(wallet_name_func),
            m_database(database)
        {}

    virtual ~ScriptPubKeyMan() {};
    virtual bool GetNewDestination(const OutputType type, CTxDestination& dest, std::string& error) { return false; }
    virtual isminetype IsMine(const CScript& script) const { return ISMINE_NO; }

    virtual bool IsCrypted() const { return false; }
    virtual bool IsLocked() const { return false; }
    virtual bool Lock() { return false; }

    virtual bool Unlock(const CKeyingMaterial& vMasterKeyIn, bool accept_no_keys = false) { return false; }
    virtual bool Encrypt(CKeyingMaterial& vMasterKeyIn, WalletBatch* batch) { return false; }

    virtual bool GetReservedDestination(const OutputType type, bool internal, CTxDestination& address, int64_t& index, CKeyPool& keypool) { return false; }
    virtual void KeepDestination(int64_t index) {}
    virtual void ReturnDestination(int64_t index, bool internal, const CTxDestination& addr) {}

    virtual bool TopUp(unsigned int size = 0) { return false; }

    //! Mark unused addresses as being used
    virtual void MarkUnusedAddresses(const CScript& script) {}

    //! Upgrade stored CKeyMetadata objects to store key origin info as KeyOriginInfo
    virtual void UpgradeKeyMetadata() {}

    /** Sets up the key generation stuff.
      * Returns false if already setup or setup fails, true if setup is successful
      * Set force=true to make it re-setup if already setup, used for upgrades
      */
    virtual bool SetupGeneration(bool force = false) { return false; }

    /* Returns true if HD is enabled */
    virtual bool IsHDEnabled() const { return false; }

    /* Returns true if the wallet can give out new addresses. This means it has keys in the keypool or can generate new keys */
    virtual bool CanGetAddresses(bool internal = false) { return false; }

    /** Upgrades the wallet to the specified version */
    virtual bool Upgrade(int prev_version, int new_version, std::string& error) { return false; }

    virtual bool HavePrivateKeys() const { return false; }

    virtual int64_t GetOldestKeyPoolTime() { return GetTime(); }

    virtual size_t KeypoolCountExternalKeys() { return 0; }
    virtual unsigned int GetKeypoolSize() const { return 0; }

    virtual int64_t GetTimeFirstKey() const { return 0; }

    virtual const CKeyMetadata* GetMetadata(uint160 id) const { return nullptr; }

    virtual std::unique_ptr<SigningProvider> GetSigningProvider(const CScript& script) const { return nullptr; }
    virtual bool CanProvide(const CScript& script, SignatureData& sigdata) { return false; }

    virtual uint256 GetID() const { return uint256(); }

    /** Prepends the wallet name in logging output to ease debugging in multi-wallet use cases */
    template<typename... Params>
    void WalletLogPrintf(std::string fmt, Params... parameters) const {
        LogPrintf(("%s " + fmt).c_str(), GetDisplayName(), parameters...);
    };

    /** Watch-only address added */
    boost::signals2::signal<void (bool fHaveWatchOnly)> NotifyWatchonlyChanged;

    /** Keypool has new keys */
    boost::signals2::signal<void ()> NotifyCanGetAddressesChanged;
};

class LegacyScriptPubKeyMan : public ScriptPubKeyMan, public FillableSigningProvider
{
protected:
    VersionFunc CanSupportFeature; // Function pointer to function that indicates whether the feature is supported
    SetVersionFunc SetMinVersion; // Function pointer to SetMinVersion in the wallet

public:
    LegacyScriptPubKeyMan(FlagSetFunc is_set_func, FlagFuncWithDB unset_flag_func, NameFunc wallet_name_func, VersionFunc feature_sup_func, SetVersionFunc set_version_func, std::shared_ptr<WalletDatabase> database)
        :   ScriptPubKeyMan(is_set_func, unset_flag_func, wallet_name_func, database),
            CanSupportFeature(feature_sup_func),
            SetMinVersion(set_version_func)
        {}

    bool GetNewDestination(const OutputType type, CTxDestination& dest, std::string& error) override EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore);
    isminetype IsMine(const CScript& script) const override;

    bool IsCrypted() const override;
    bool IsLocked() const override;
    bool Lock() override;

    bool Unlock(const CKeyingMaterial& vMasterKeyIn, bool accept_no_keys = false) override;
    bool Encrypt(CKeyingMaterial& vMasterKeyIn, WalletBatch* batch) override;

    bool GetReservedDestination(const OutputType type, bool internal, CTxDestination& address, int64_t& index, CKeyPool& keypool) override;
    void KeepDestination(int64_t index) override;
    void ReturnDestination(int64_t index, bool internal, const CTxDestination& addr) override;

    bool TopUp(unsigned int size = 0) override;

    void MarkUnusedAddresses(const CScript& script) override;

    void UpgradeKeyMetadata() override EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore);

    bool IsHDEnabled() const override;

    bool SetupGeneration(bool force = false) override;

    bool Upgrade(int prev_version, int new_version, std::string& error) override;

    bool HavePrivateKeys() const override;

    int64_t GetOldestKeyPoolTime() override;
    size_t KeypoolCountExternalKeys() override EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore);
    unsigned int GetKeypoolSize() const override;

    int64_t GetTimeFirstKey() const override;

    const CKeyMetadata* GetMetadata(uint160 id) const override;

    bool CanGetAddresses(bool internal = false) override;

    std::unique_ptr<SigningProvider> GetSigningProvider(const CScript& script) const override;

    bool CanProvide(const CScript& script, SignatureData& sigdata) override;

    uint256 GetID() const override;
};

#endif // BITCOIN_WALLET_SCRIPTPUBKEYMAN_H
