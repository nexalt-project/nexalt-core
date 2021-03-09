// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <miner.h>

#include <amount.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <hash.h>
#include <net.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <script/standard.h>
#include <timedata.h>
#include <util/moneystr.h>
#include <util/system.h>
#include <validationinterface.h>

#include <algorithm>
#include <queue>
#include <utility>

#include <wallet/rpcwallet.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>
//for levelDb
#include <cassert>
#include "leveldb/db.h"
#include <leveldb/c.h>
#include <sstream>
#include <string>
#include <iostream>
#include <masternode.h>
#include <core_io.h>
#include "stake.h"
//for reward distribution
#include <util/strencodings.h>
#include <crypto/ripemd160.h>
#include <key_io.h>
#include <keystore.h>
#include <rpc/protocol.h>
#include <rpc/util.h>
#include <tinyformat.h>
using namespace std;

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockWeight = 0;
std::string this_is_my_key="";
uint64_t nLastBlockSize = 0;
std::vector <std::string> KeyValue;

vector<string> explode_miner_data( const string &delimiter, const string &explodeme);

vector<string> explode_miner_data( const string &delimiter, const string &str)
{
    vector<string> arr;

    int strleng = str.length();
    int delleng = delimiter.length();
    if (delleng==0)
        return arr;//no change

    int i=0;
    int k=0;
    while( i<strleng )
    {
        int j=0;
        while (i+j<strleng && j<delleng && str[i+j]==delimiter[j])
            j++;
        if (j==delleng)//found delimiter
        {
            arr.push_back(  str.substr(k, i-k) );
            i+=delleng;
            k=i;
        }
        else
        {
            i++;
        }
    }
    arr.push_back(  str.substr(k, i-k) );
    return arr;
}

int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev, bool isProofOfStake)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime = std::max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());

    if (nOldTime < nNewTime)
        pblock->nTime = nNewTime;

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks)
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams, isProofOfStake);

    return nNewTime - nOldTime;
}

BlockAssembler::Options::Options() {
    blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);
    nBlockMaxWeight = DEFAULT_BLOCK_MAX_WEIGHT;
}

BlockAssembler::BlockAssembler(const CChainParams& params, const Options& options) : chainparams(params)
{
    blockMinFeeRate = options.blockMinFeeRate;
    // Limit weight to between 4K and MAX_BLOCK_WEIGHT-4K for sanity:
    nBlockMaxWeight = std::max<size_t>(4000, std::min<size_t>(MAX_BLOCK_WEIGHT - 4000, options.nBlockMaxWeight));
}

static BlockAssembler::Options DefaultOptions()
{
    // Block resource limits
    // If -blockmaxweight is not given, limit to DEFAULT_BLOCK_MAX_WEIGHT
    BlockAssembler::Options options;
    options.nBlockMaxWeight = gArgs.GetArg("-blockmaxweight", DEFAULT_BLOCK_MAX_WEIGHT);
    CAmount n = 0;
    if (gArgs.IsArgSet("-blockmintxfee") && ParseMoney(gArgs.GetArg("-blockmintxfee", ""), n)) {
        options.blockMinFeeRate = CFeeRate(n);
    } else {
        options.blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);
    }
    return options;
}

BlockAssembler::BlockAssembler(const CChainParams& params) : BlockAssembler(params, DefaultOptions()) {}

void BlockAssembler::resetBlock()
{
    inBlock.clear();

    // Reserve space for coinbase tx
    //nBlockSize = 1000;
    nBlockWeight = 4000;
    nBlockSigOpsCost = 400;
    fIncludeWitness = false;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;
}

Optional<int64_t> BlockAssembler::m_last_block_num_txs{nullopt};
Optional<int64_t> BlockAssembler::m_last_block_weight{nullopt};

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewStake(bool fMineWitnessTx, bool fProofOfStake, int64_t* pTotalFees,
                                                               int32_t txProofTime, int32_t nTimeLimit)
{
    int64_t nTimeStart = GetTimeMicros();
    int64_t currentTime = GetTime();
    uint32_t nposstarttime = 0;
    nposstarttime = START_POS_BLOCK;
    if (currentTime << nposstarttime){
        throw std::runtime_error(
                strprintf("%s: TestBlockValidity failed: PoS not started yet", __func__));
    }


    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());

    if(!pblocktemplate.get())
        return nullptr;
    pblock = &pblocktemplate->block; // pointer for convenience

    // Add dummy coinbase tx as first transaction
    pblock->vtx.emplace_back();
    // Add dummy coinstake tx as second transaction
    if(fProofOfStake)
        pblock->vtx.emplace_back();
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOpsCost.push_back(-1); // updated at end

    LOCK2(cs_main, mempool.cs);
    CBlockIndex* pindexPrev = chainActive.Tip();
    assert(pindexPrev != nullptr);
    nHeight = pindexPrev->nHeight + 1;

    pblock->nVersion = ComputeBlockVersion(pindexPrev, chainparams.GetConsensus());
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand())
        pblock->nVersion = gArgs.GetArg("-blockversion", pblock->nVersion);


    if(txProofTime == 0) {
        txProofTime = GetAdjustedTime();
    }
    pblock->nTime = txProofTime;
    if (!fProofOfStake)
        UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev, fProofOfStake);

    //difficulty adjustment block should be pow
    if ((pblock->GetBlockTime() >= NEW_DIFFICULTY_RULE)) {
        const CBlockIndex *pindexLast;
        const CChainParams &chainParams = Params();
        pindexLast = GetLastBlockIndex(pindexPrev, fProofOfStake);
        if ((pindexPrev->nHeight + 1) % chainparams.GetConsensus().DifficultyAdjustmentInterval() == 0) {
            return nullptr;
        }
    }
    pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus(),fProofOfStake);
    const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();

    nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
                      ? nMedianTimePast
                      : pblock->GetBlockTime();


    nLastBlockTx = nBlockTx;
    //nLastBlockSize = nBlockSize;
    nLastBlockWeight = nBlockWeight;

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vout.resize(1);
    // Decide whether to include witness transactions
    // This is only needed in case the witness softfork activation is reverted
    // (which would require a very deep reorganization) or when
    // -promiscuousmempoolflags is used.
    // TODO: replace this with a call to main to assess validity of a mempool
    // transaction (which in most cases can be a no-op).
    fIncludeWitness = true;//IsWitnessEnabled(pindexPrev, chainparams.GetConsensus()) && fMineWitnessTx;
    if (fProofOfStake){
        // Height first in coinbase required for block.version=2
        coinbaseTx.vin[0].scriptSig = (CScript() << nHeight) + COINBASE_FLAGS;
        assert(coinbaseTx.vin[0].scriptSig.size() <= 100);
        coinbaseTx.vout[0].SetEmpty();
    }
    originalRewardTx = coinbaseTx;

    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));

    std::string wallet_name = "";
    std::shared_ptr <CWallet> pwallet = GetWallet(wallet_name);
    CWallet *const wallet_stake = pwallet.get();

    if (fProofOfStake && !stake->CreateBlockStake(wallet_stake, pblock)) {
        return nullptr;
    }

    if (fProofOfStake)
        originalRewardTx = CMutableTransaction(*pblock->vtx[1]);


    int nPackagesSelected = 0;
    int nDescendantsUpdated = 0;
    addPackageTxs(nPackagesSelected, nDescendantsUpdated);
    pblocktemplate->vchCoinbaseCommitment = GenerateCoinbaseCommitment(*pblock, pindexPrev, chainparams.GetConsensus(), fProofOfStake);
    pblocktemplate->vTxFees[0] = nFees;

    // The total fee is the Fees minus the Refund
    if (pTotalFees)
        *pTotalFees = nFees ;

    // Fill in header
    pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
    pblock->nNonce         = 0;
    pblocktemplate->vTxSigOpsCost[0] = WITNESS_SCALE_FACTOR * GetLegacySigOpCount(*pblock->vtx[0]);

    CValidationState state;
    if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev, false, false)) {
        if (!fProofOfStake) {
            throw std::runtime_error(
                    strprintf("%s: TestBlockValidity failed: %s", __func__, FormatStateMessage(state)));
        }
        return nullptr;
    }
    return std::move(pblocktemplate);
}


bool IsSponsorSaved(std::string wallet_name){
    std::string std_data_dir = GetDataDir().string();
    leveldb::DB *db_my;
    leveldb::Options options_my;
    options_my.create_if_missing = true;
    std::string valueToCheck = "";
    std::string value = "";
    if(wallet_name == ""){
        std::string StringKeyToShow = "StringKeyToShow";
        std::string StringKey = "StringKey";
        leveldb::Status status_my = leveldb::DB::Open(options_my, std_data_dir + "/myKey", &db_my);
        if (status_my.ok()) status_my = db_my->Get(leveldb::ReadOptions(), StringKeyToShow, &valueToCheck);
        if (status_my.ok()) status_my = db_my->Get(leveldb::ReadOptions(), StringKey, &value);
        delete db_my;
        if(valueToCheck == "" && value ==""){
            return false;
        }else{
            return true;
        }
    }else{
        std::string wallet_name_show = wallet_name +"_show";
        leveldb::Status status_my = leveldb::DB::Open(options_my, std_data_dir + "/myKey", &db_my);
        if (status_my.ok()) status_my = db_my->Get(leveldb::ReadOptions(), wallet_name_show, &valueToCheck);
        if (status_my.ok()) status_my = db_my->Get(leveldb::ReadOptions(), wallet_name, &value);
        delete db_my;
        if(valueToCheck == "" && value ==""){
            return false;
        }else{
            return true;
        }
    }
}

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock(const CScript& scriptPubKeyIn, std::string mlc , bool fMineWitnessTx)
{
    int64_t nTimeStart = GetTimeMicros();

    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());

    if(!pblocktemplate.get())
        return nullptr;
    pblock = &pblocktemplate->block; // pointer for convenience

    // Add dummy coinbase tx as first transaction
    pblock->vtx.emplace_back();
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOpsCost.push_back(-1); // updated at end

    LOCK2(cs_main, mempool.cs);
    CBlockIndex* pindexPrev = chainActive.Tip();
    assert(pindexPrev != nullptr);
    nHeight = pindexPrev->nHeight + 1;

    pblock->nVersion = ComputeBlockVersion(pindexPrev, chainparams.GetConsensus());
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand())
        pblock->nVersion = gArgs.GetArg("-blockversion", pblock->nVersion);

    pblock->nTime = GetAdjustedTime();
    const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();

    nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
                       ? nMedianTimePast
                       : pblock->GetBlockTime();

    // Decide whether to include witness transactions
    // This is only needed in case the witness softfork activation is reverted
    // (which would require a very deep reorganization).
    // Note that the mempool would accept transactions with witness data before
    // IsWitnessEnabled, but we would only ever mine blocks after IsWitnessEnabled
    // unless there is a massive block reorganization with the witness softfork
    // not activated.
    // TODO: replace this with a call to main to assess validity of a mempool
    // transaction (which in most cases can be a no-op).
    //fIncludeWitness = IsWitnessEnabled(pindexPrev, chainparams.GetConsensus());
    fIncludeWitness = true;

    string mlc_capabilities = "";
    string mlc_wallet_name = "";
    if(mlc != "ok") {
        vector <string> cap_wallet_name = explode_miner_data("**", mlc);
        mlc_capabilities = cap_wallet_name[0];
        mlc_wallet_name = cap_wallet_name[1];
    }
    bool SpKey = IsSponsorSaved(mlc_wallet_name);
    std::string std_data_dir = GetDataDir().string();
    //my key db
    leveldb::DB *db_my;
    leveldb::Options options_my;
    options_my.create_if_missing = true;
    //mlc db
    leveldb::DB *db;
    leveldb::Options options;
    options.create_if_missing = true;
    std::string value_sponser_up;
    //open db.
    if(mlc_wallet_name == ""){
        std::string StringKey = "StringKey";
        std::string value_my;
        leveldb::Status status_own = leveldb::DB::Open(options_my, std_data_dir + "/myKey", &db_my);
        if (status_own.ok()) status_own = db_my->Get(leveldb::ReadOptions(), StringKey, &value_my);
        delete db_my;
        if(value_my !="") {
            this_is_my_key = value_my;
            for (int i = 1; i < 11; ++i) {
                value_sponser_up = "";
                leveldb::Status status = leveldb::DB::Open(options, std_data_dir + "/mlc", &db);
                if (status.ok()) status = db->Get(leveldb::ReadOptions(), value_my, &value_sponser_up);
                delete db;
                if (value_sponser_up == "") {
                } else {
                    KeyValue.push_back(value_sponser_up);
                    value_my = value_sponser_up;
                }
            }
        }
    }else{
        std::string StringKey = mlc_wallet_name;
        std::string value_my;
        leveldb::Status status_own = leveldb::DB::Open(options_my, std_data_dir + "/myKey", &db_my);
        if (status_own.ok()) status_own = db_my->Get(leveldb::ReadOptions(), StringKey, &value_my);
        delete db_my;
        if(value_my !="") {
            this_is_my_key = value_my;
            for (int i = 1; i < 11; ++i) {
                value_sponser_up = "";
                leveldb::Status status = leveldb::DB::Open(options, std_data_dir + "/mlc", &db);
                if (status.ok()) status = db->Get(leveldb::ReadOptions(), value_my, &value_sponser_up);
                delete db;
                if (value_sponser_up == "") {
                } else {
                    KeyValue.push_back(value_sponser_up);
                    value_my = value_sponser_up;
                }
            }
        }
    }

    return nullptr;
    int nPackagesSelected = 0;
    int nDescendantsUpdated = 0;
    addPackageTxs(nPackagesSelected, nDescendantsUpdated);

    int64_t nTime1 = GetTimeMicros();

    m_last_block_num_txs = nBlockTx;
    m_last_block_weight = nBlockWeight;

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;

    std::string value_my =  this_is_my_key;
    //value_my = this_is_my_key;
    double mlcDistribution = ((GetBlockSubsidy(nHeight, chainparams.GetConsensus()) * 33.34) / 100 ) / COIN;
    double uplineReward = UpLineReward(nHeight);
    double mainminerReward = nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus());
    bool  ismagic = IsMagicBlock(nHeight);
    int64_t timeNow = GetTime();

    if (timeNow > START_POS_BLOCK ){
        mainminerReward = nFees + MainMinerReward(nHeight);
        if (timeNow > START_POS_BLOCK_V2){
            mainminerReward = nFees + MinerRewardV2(nHeight);
        }
    }else{
        mainminerReward = (nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus())) - (mlcDistribution * COIN);
        double subsidy = (GetBlockSubsidy(nHeight, chainparams.GetConsensus()) * 33.34 / 100 ) / COIN;
        uplineReward = ((subsidy * 10) /100) * COIN ;
    }

    if (ismagic){
        mainminerReward = nFees + MagicBlockReward(nHeight, GetBlockSubsidy(nHeight, chainparams.GetConsensus()));
    }
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vout.resize(1);
    //converting his own key....
    CTxDestination dest = DecodeDestination(value_my);
    bool isValid = IsValidDestination(dest);
    CScript scriptPubKey_main;
    if (isValid) {
        std::string currentAddress = EncodeDestination(dest);
        scriptPubKey_main = GetScriptForDestination(dest);
    }

    CScript mnPayee;
    CAmount mnReward = GetMasternodePosReward(nHeight, GetBlockSubsidy(nHeight, chainparams.GetConsensus()));;
    CAmount minerReward = 0;
    CAmount powReward = GetBlockSubsidy(nHeight, chainparams.GetConsensus()) ;
    CAmount totalReward =  nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus());

    if(timeNow < START_POS_BLOCK_V2){
        for (int i = 1; i < 11; i++) {
            if (KeyValue[i-1] != "") {
            coinbaseTx.vout.resize(i + 1);
            CTxDestination dest = DecodeDestination(KeyValue[i-1]);
            std::string wallet_name;
            if(mlc_wallet_name == ""){
                wallet_name = "";
            }else{
                wallet_name = mlc_wallet_name;
            }
            std::shared_ptr <CWallet> wallet = GetWallet(wallet_name);
            isminetype mine = IsMine(*wallet, dest);
            if (bool(mine & ISMINE_SPENDABLE) == 1){
                throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, "Invalid MLC Tree"));
            }else{
                bool isValid = IsValidDestination(dest);
                CScript scriptPubKey;
                if (isValid) {
                    std::string currentAddress = EncodeDestination(dest);
                    scriptPubKey = GetScriptForDestination(dest);
                }
                coinbaseTx.vout[i].scriptPubKey = scriptPubKey;
                coinbaseTx.vout[i].nValue = uplineReward;
            }
            }else{
                throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, "Invalid MLC Tree"));
            }
        }
    }
    if (SpKey){
        coinbaseTx.vout[0].scriptPubKey = scriptPubKey_main;
    }else{
        coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn;
    }
    coinbaseTx.vout[0].nValue = mainminerReward;


    coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;
    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));
    pblocktemplate->vchCoinbaseCommitment = GenerateCoinbaseCommitment(*pblock, pindexPrev, chainparams.GetConsensus(),false);
    pblocktemplate->vTxFees[0] = -nFees;

    LogPrintf("CreateNewBlock(): block weight: %u txs: %u fees: %ld sigops %d\n", GetBlockWeight(*pblock), nBlockTx, nFees, nBlockSigOpsCost);


    uint256 hash = uint256S("9825e799f2a1f012e11b11d0d2a4166ac0524389b0493281c0778d9eb492321f");
    pblock->hashPrevBlock = hash;

    UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus(), false);
    pblock->nNonce         = 0;
    pblocktemplate->vTxSigOpsCost[0] = WITNESS_SCALE_FACTOR * GetLegacySigOpCount(*pblock->vtx[0]);

    CValidationState state;
    if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev, false, false)) {
        throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, FormatStateMessage(state)));
    }
    int64_t nTime2 = GetTimeMicros();

    LogPrint(BCLog::BENCH, "CreateNewBlock() packages: %.2fms (%d packages, %d updated descendants), validity: %.2fms (total %.2fms)\n", 0.001 * (nTime1 - nTimeStart), nPackagesSelected, nDescendantsUpdated, 0.001 * (nTime2 - nTime1), 0.001 * (nTime2 - nTimeStart));

    return std::move(pblocktemplate);
}

void BlockAssembler::onlyUnconfirmed(CTxMemPool::setEntries& testSet)
{
    for (CTxMemPool::setEntries::iterator iit = testSet.begin(); iit != testSet.end(); ) {
        // Only test txs not already in the block
        if (inBlock.count(*iit)) {
            testSet.erase(iit++);
        }
        else {
            iit++;
        }
    }
}

bool BlockAssembler::TestPackage(uint64_t packageSize, int64_t packageSigOpsCost) const
{
    // TODO: switch to weight-based accounting for packages instead of vsize-based accounting.
    if (nBlockWeight + WITNESS_SCALE_FACTOR * packageSize >= nBlockMaxWeight)
        return false;
    if (nBlockSigOpsCost + packageSigOpsCost >= MAX_BLOCK_SIGOPS_COST)
        return false;
    return true;
}

// Perform transaction-level checks before adding to block:
// - transaction finality (locktime)
// - premature witness (in case segwit transactions are added to mempool before
//   segwit activation)
bool BlockAssembler::TestPackageTransactions(const CTxMemPool::setEntries& package)
{
    for (CTxMemPool::txiter it : package) {
        if (!IsFinalTx(it->GetTx(), nHeight, nLockTimeCutoff)) {
            return false;
        }
        if (!fIncludeWitness && it->GetTx().HasWitness()) {
            return false;
        }
    }
    return true;
}

void BlockAssembler::AddToBlock(CTxMemPool::txiter iter)
{
    pblock->vtx.emplace_back(iter->GetSharedTx());
    pblocktemplate->vTxFees.push_back(iter->GetFee());
    pblocktemplate->vTxSigOpsCost.push_back(iter->GetSigOpCost());
    nBlockWeight += iter->GetTxWeight();
    ++nBlockTx;
    nBlockSigOpsCost += iter->GetSigOpCost();
    nFees += iter->GetFee();
    inBlock.insert(iter);

    bool fPrintPriority = gArgs.GetBoolArg("-printpriority", DEFAULT_PRINTPRIORITY);
    if (fPrintPriority) {
        LogPrintf("fee %s txid %s\n",
                  CFeeRate(iter->GetModifiedFee(), iter->GetTxSize()).ToString(),
                  iter->GetTx().GetHash().ToString());
    }
}

int BlockAssembler::UpdatePackagesForAdded(const CTxMemPool::setEntries& alreadyAdded,
        indexed_modified_transaction_set &mapModifiedTx)
{
    int nDescendantsUpdated = 0;
    for (CTxMemPool::txiter it : alreadyAdded) {
        CTxMemPool::setEntries descendants;
        mempool.CalculateDescendants(it, descendants);
        // Insert all descendants (not yet in block) into the modified set
        for (CTxMemPool::txiter desc : descendants) {
            if (alreadyAdded.count(desc))
                continue;
            ++nDescendantsUpdated;
            modtxiter mit = mapModifiedTx.find(desc);
            if (mit == mapModifiedTx.end()) {
                CTxMemPoolModifiedEntry modEntry(desc);
                modEntry.nSizeWithAncestors -= it->GetTxSize();
                modEntry.nModFeesWithAncestors -= it->GetModifiedFee();
                modEntry.nSigOpCostWithAncestors -= it->GetSigOpCost();
                mapModifiedTx.insert(modEntry);
            } else {
                mapModifiedTx.modify(mit, update_for_parent_inclusion(it));
            }
        }
    }
    return nDescendantsUpdated;
}

// Skip entries in mapTx that are already in a block or are present
// in mapModifiedTx (which implies that the mapTx ancestor state is
// stale due to ancestor inclusion in the block)
// Also skip transactions that we've already failed to add. This can happen if
// we consider a transaction in mapModifiedTx and it fails: we can then
// potentially consider it again while walking mapTx.  It's currently
// guaranteed to fail again, but as a belt-and-suspenders check we put it in
// failedTx and avoid re-evaluation, since the re-evaluation would be using
// cached size/sigops/fee values that are not actually correct.
bool BlockAssembler::SkipMapTxEntry(CTxMemPool::txiter it, indexed_modified_transaction_set &mapModifiedTx, CTxMemPool::setEntries &failedTx)
{
    assert (it != mempool.mapTx.end());
    return mapModifiedTx.count(it) || inBlock.count(it) || failedTx.count(it);
}

void BlockAssembler::SortForBlock(const CTxMemPool::setEntries& package, std::vector<CTxMemPool::txiter>& sortedEntries)
{
    // Sort package by ancestor count
    // If a transaction A depends on transaction B, then A's ancestor count
    // must be greater than B's.  So this is sufficient to validly order the
    // transactions for block inclusion.
    sortedEntries.clear();
    sortedEntries.insert(sortedEntries.begin(), package.begin(), package.end());
    std::sort(sortedEntries.begin(), sortedEntries.end(), CompareTxIterByAncestorCount());
}

// This transaction selection algorithm orders the mempool based
// on feerate of a transaction including all unconfirmed ancestors.
// Since we don't remove transactions from the mempool as we select them
// for block inclusion, we need an alternate method of updating the feerate
// of a transaction with its not-yet-selected ancestors as we go.
// This is accomplished by walking the in-mempool descendants of selected
// transactions and storing a temporary modified state in mapModifiedTxs.
// Each time through the loop, we compare the best transaction in
// mapModifiedTxs with the next transaction in the mempool to decide what
// transaction package to work on next.
void BlockAssembler::addPackageTxs(int &nPackagesSelected, int &nDescendantsUpdated)
{
    // mapModifiedTx will store sorted packages after they are modified
    // because some of their txs are already in the block
    indexed_modified_transaction_set mapModifiedTx;
    // Keep track of entries that failed inclusion, to avoid duplicate work
    CTxMemPool::setEntries failedTx;

    // Start by adding all descendants of previously added txs to mapModifiedTx
    // and modifying them for their already included ancestors
    UpdatePackagesForAdded(inBlock, mapModifiedTx);

    CTxMemPool::indexed_transaction_set::index<ancestor_score>::type::iterator mi = mempool.mapTx.get<ancestor_score>().begin();
    CTxMemPool::txiter iter;

    // Limit the number of attempts to add transactions to the block when it is
    // close to full; this is just a simple heuristic to finish quickly if the
    // mempool has a lot of entries.
    const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
    int64_t nConsecutiveFailed = 0;

    while (mi != mempool.mapTx.get<ancestor_score>().end() || !mapModifiedTx.empty())
    {
        // First try to find a new transaction in mapTx to evaluate.
        if (mi != mempool.mapTx.get<ancestor_score>().end() &&
            SkipMapTxEntry(mempool.mapTx.project<0>(mi), mapModifiedTx, failedTx)) {
            ++mi;
            continue;
        }

        // Now that mi is not stale, determine which transaction to evaluate:
        // the next entry from mapTx, or the best from mapModifiedTx?
        bool fUsingModified = false;

        modtxscoreiter modit = mapModifiedTx.get<ancestor_score>().begin();
        if (mi == mempool.mapTx.get<ancestor_score>().end()) {
            // We're out of entries in mapTx; use the entry from mapModifiedTx
            iter = modit->iter;
            fUsingModified = true;
        } else {
            // Try to compare the mapTx entry to the mapModifiedTx entry
            iter = mempool.mapTx.project<0>(mi);
            if (modit != mapModifiedTx.get<ancestor_score>().end() &&
                CompareTxMemPoolEntryByAncestorFee()(*modit, CTxMemPoolModifiedEntry(iter))) {
                // The best entry in mapModifiedTx has higher score
                // than the one from mapTx.
                // Switch which transaction (package) to consider
                iter = modit->iter;
                fUsingModified = true;
            } else {
                // Either no entry in mapModifiedTx, or it's worse than mapTx.
                // Increment mi for the next loop iteration.
                ++mi;
            }
        }

        // We skip mapTx entries that are inBlock, and mapModifiedTx shouldn't
        // contain anything that is inBlock.
        assert(!inBlock.count(iter));

        uint64_t packageSize = iter->GetSizeWithAncestors();
        CAmount packageFees = iter->GetModFeesWithAncestors();
        int64_t packageSigOpsCost = iter->GetSigOpCostWithAncestors();
        if (fUsingModified) {
            packageSize = modit->nSizeWithAncestors;
            packageFees = modit->nModFeesWithAncestors;
            packageSigOpsCost = modit->nSigOpCostWithAncestors;
        }

        if (packageFees < blockMinFeeRate.GetFee(packageSize)) {
            // Everything else we might consider has a lower fee rate
            return;
        }

        if (!TestPackage(packageSize, packageSigOpsCost)) {
            if (fUsingModified) {
                // Since we always look at the best entry in mapModifiedTx,
                // we must erase failed entries so that we can consider the
                // next best entry on the next loop iteration
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            ++nConsecutiveFailed;

            if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES && nBlockWeight >
                                                                 nBlockMaxWeight - 4000) {
                // Give up if we're close to full and haven't succeeded in a while
                break;
            }
            continue;
        }

        CTxMemPool::setEntries ancestors;
        uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
        std::string dummy;
        mempool.CalculateMemPoolAncestors(*iter, ancestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy, false);

        onlyUnconfirmed(ancestors);
        ancestors.insert(iter);

        // Test if all tx's are Final
        if (!TestPackageTransactions(ancestors)) {
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            continue;
        }

        // This transaction will make it in; reset the failed counter.
        nConsecutiveFailed = 0;

        // Package can be added. Sort the entries in a valid order.
        std::vector<CTxMemPool::txiter> sortedEntries;
        SortForBlock(ancestors, sortedEntries);

        for (size_t i=0; i<sortedEntries.size(); ++i) {
            AddToBlock(sortedEntries[i]);
            // Erase from the modified set, if present
            mapModifiedTx.erase(sortedEntries[i]);
        }

        ++nPackagesSelected;

        // Update transactions that depend on each of these
        nDescendantsUpdated += UpdatePackagesForAdded(ancestors, mapModifiedTx);
    }
}

void IncrementExtraNonce(CBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
}
bool ProcessBlockFound(CBlock* pblock, CWallet& wallet)
{
    const CChainParams& chainparams = Params();
    // Found a solution (stake)
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != chainActive.Tip()->GetBlockHash())
            return error("Nexalt : generated block is stale");


        auto locked_chain = wallet.chain().lock();
        for(const CTxIn& vin : pblock->vtx[1]->vin) {
            if (wallet.IsSpent(*locked_chain,vin.prevout.hash, vin.prevout.n)) {
                return error("nexalt : Gen block stake is invalid - UTXO spent");
            }
        }
    }

    CAmount generated = GetBlockSubsidy(chainActive.Height()+1,chainparams.GetConsensus() );
    if (pblock->nTime > POS_REWARD_V3){
        generated -= MasterRewardV3(chainActive.Height()+1);
    }else{
        generated -= GetMasternodePosReward(chainActive.Height()+1, generated);
    }
    generated -= GetMasternodePosReward(chainActive.Height()+1, generated);
    LogPrintf("generated %s\n", FormatMoney(generated));

    // Process this block the same as if we had received it from another node
    const CChainParams& chainParams = Params();
    CValidationState state;
    std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
    if (!ProcessNewBlock(chainParams ,shared_pblock  , false, nullptr)) {
        return error("Nexalt : ProcessNewBlock, block not accepted");
    }

    {
        LOCK(stake->stakeMiner.lock);
        stake->stakeMiner.nBlocksAccepted++;
    }

    return true;
}
