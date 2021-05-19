// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_verify.h>

#include <consensus/consensus.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <consensus/validation.h>

// TODO remove the following dependencies
#include <chain.h>
#include <coins.h>
#include <util/moneystr.h>

#include <cassert>
#include "leveldb/db.h"
#include <leveldb/c.h>
#include <sstream>
#include <string>
#include <iostream>
#ifdef ENABLE_WALLET
#include <../wallet/rpcwallet.h>
#endif
#include <../wallet/coincontrol.h>
#include <../wallet/feebumper.h>
#include <../wallet/rpcwallet.h>
#include <../wallet/wallet.h>
#include <../wallet/walletdb.h>
#include <../wallet/walletutil.h>
#include <future>
#include <stdint.h>
#include <core_io.h>
#include <key_io.h>

#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <key_io.h>
#include <script/script.h>
#include <script/standard.h>
#include <serialize.h>
#include <streams.h>
#include <univalue.h>
#include <util/system.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
using namespace std;

vector <string> explode_raw_tx_verify(const string &delimiter, const string &explodeme);

vector <string> explode_raw_tx_verify(const string &delimiter, const string &str) {
    vector <string> arr;

    int strleng = str.length();
    int delleng = delimiter.length();
    if (delleng == 0)
        return arr;//no change

    int i = 0;
    int k = 0;
    while (i < strleng) {
        int j = 0;
        while (i + j < strleng && j < delleng && str[i + j] == delimiter[j])
            j++;
        if (j == delleng)//found delimiter
        {
            arr.push_back(str.substr(k, i - k));
            i += delleng;
            k = i;
        } else {
            i++;
        }
    }
    arr.push_back(str.substr(k, i - k));
    return arr;
}

std::vector<std::string> HexAddr = { "58374348377031714153313152544a345877566667514c36454d7456386874597866",
                                          "5839584177354e6a33625571333765484b6d59506e755764793555386e6b6b42664b",
                                          "57753971535a7a63466963506e4e6f33735a394c435a47706d526d4b7a7446384e6a",
                                          "583765467070355062544b5462796178793646376e326865736564346234726d6e52",
                                          "5779684c4c503938504b5a724e53786b61316a577471394e4676564662596d4e7345",
                                          "57744c757476425032665045693344646f6d71756e79325171755675365653427971",
                                          "5836735636663131316e43324d37674470546b7476706a7454615668665644475356",
                                          "5771754d7742694a4650346d7a6975434476366f4646623536784e727a3645447446",
                                          "57757153526246536f6e4c775a524e515955636e6365467236504e716834324b3863",
                                          "57706e42666442727344484a4e6536765a3838374474656935615a6b4a5732346e39",
};
std::vector<std::string> HexAddrPow = {
        "58374348377031714153313152544a345877566667514c36454d7456386874597866",
        "5837595373457346744c50685433574c57536577616661545863336773796f386f66",
        "58366a6e3748454773574e744c726d41537a786f58736f5568477567557a516a756a",
        "5838796745446957616633444d614b37625932546d6f4c734a584554437139675438",
        "58357a6d59323332477766573862316775565a69586f69516d6a64514b357556626e",
        "5831645046414750596a4a74436b464b6758736a784175464770595a313675487739",
        "58384d39666742667363583731377443784557334350534b4e427848755479433971",
        "583462646b7a54537745344e33507a4d50326765503955316a425736327a61384e7a",
        "584133665075656d4c6a59467174395270614b4d4741483657357253774871754c45",
        "58424351566e5555586d637a4c6276326563584a5341766e617951786a374d4d6d79",
        "58343651767a4667757474526a6f566a465576754e5861446b337156524e47463570",
        "5833664c65466165726e665433506e47767471376d4469314a67346977515378344a",
        "5838486157414e737738596d55784766463252344e6950396279324d4a5358715362",
        "58316f39486a63774b734e4564676a6377536e327859577832514e64785576514234",
        "58326847354a714666354a376d74424875325637636b334741725679613877586a4b",
        "58376d615a79705459597342554838555469663631506a6e50727141325633467351",
        "5833766f6e70565170393862444b64756a397467707659704157336b513458634541",
        "583752555533366644464a4d643669684e37444459634a7a6e5461645977414c3232",
        "583470664256696669646b4456636a4770556d6b5a6138736a58557535614b735743",
        "5834384d6f38444b70614c4c4b38326363556e71694767706736593376575a54584a",
        "583634624157503866434865504633654a383473557758474c4179364d4e53584639",
        "5835626350667347427938663554344447574866635377544c6751667a3635456533",
        "58367a37346764754761446146356b3632796f7241644647656a745664544b747771",
        "5837636464346752706d7543694664355532376e4255415a73596d514a724b516745",
        "5833466b6a5034346e67484d75764a573361386a445179735a594a45746755424747",
        "58324b4c456b636b6f4e3141414b5978786172473939537961415979786853764765",
        "583865757a4e4b374c3968594b43554a6a6e50716d7445706d335a707a6137466638",
        "583974555a6279726d466431776d71754d534634425842466743516354365959384c",
        "58355739745235635638634868756b4b45774b4433515a74364b66367a7456773377",
        "5841337a69706d483834754562664a74576857326d7259447a477457554e42323673",
        "58375a465271553966334531516e43374c51374148453934345463524676615a7148",
        "5831396e5759437141454d7652745951613435376b4673716a47734838383851744e",
        "58383347696544756f58323243485a57687532526f344672315972784434514d3563",
        "58317a6b57776653614a4b585a3551506b3947514d58445056646a35327666757863",
        "5839517546477166554c55724d476b56456345714b6368533658684c4c4835466b75",
        "583878685a675a4a4d6b525a644633754b686153465558375075516e413148653437",
        "5831724a5263433542735172674163335753564a5672536d5277445652594b6e4779",
        "58345646634352467979566773424742427275794b727a57626664616b5055426258",
        "5837514c56594765354b36444841556a7a42356a4a747667363478734a4734364551",
        "58387068654a5865357641475442776b326a6e7076457035335450554e77636b7571",
};

int hex_value_tx_verify(char hex_digit) {
    switch (hex_digit) {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            return hex_digit - '0';

        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
            return hex_digit - 'A' + 10;

        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
            return hex_digit - 'a' + 10;
    }
    throw std::invalid_argument("invalid hex digit");
}

string stringToHex_tx_verify(string str) {
    static const char hex_digits[] = "0123456789abcdef";
    std::string output;
    output.reserve(str.length() * 2);
    for (unsigned char c : str) {
        output.push_back(hex_digits[c >> 4]);
        output.push_back(hex_digits[c & 15]);
    }
    return output;
}

string hexToString_tx_verify(string str) {
    const auto len = str.length();
    if (len & 1) throw std::invalid_argument("odd length");
    std::string output_string;
    output_string.reserve(len / 2);
    for (auto it = str.begin(); it != str.end();) {
        int hi = hex_value_tx_verify(*it++);
        int lo = hex_value_tx_verify(*it++);
        output_string.push_back(hi << 4 | lo);
    }
    return output_string;
}

bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
{
    if (tx.nLockTime == 0)
        return true;
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;
    for (const auto& txin : tx.vin) {
        if (!(txin.nSequence == CTxIn::SEQUENCE_FINAL))
            return false;
    }
    return true;
}

std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    assert(prevHeights->size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    // tx.nVersion is signed integer so requires cast to unsigned otherwise
    // we would be doing a signed comparison and half the range of nVersion
    // wouldn't support BIP 68.
    bool fEnforceBIP68 = static_cast<uint32_t>(tx.nVersion) >= 2
                      && flags & LOCKTIME_VERIFY_SEQUENCE;

    // Do not enforce sequence numbers as a relative lock time
    // unless we have been instructed to
    if (!fEnforceBIP68) {
        return std::make_pair(nMinHeight, nMinTime);
    }

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
        const CTxIn& txin = tx.vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            // The height of this input is not relevant for sequence locks
            (*prevHeights)[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = (*prevHeights)[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
            int64_t nCoinTime = block.GetAncestor(std::max(nCoinHeight-1, 0))->GetMedianTimePast();
            // NOTE: Subtract 1 to maintain nLockTime semantics
            // BIP 68 relative lock times have the semantics of calculating
            // the first block or time at which the transaction would be
            // valid. When calculating the effective block time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid block
            // time or height.  Thus we subtract 1 from the calculated
            // time or height.

            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the block containing the
            // txout being spent, which is the median time past of the
            // block prior.
            nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
        } else {
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair)
{
    assert(block.pprev);
    int64_t nBlockTime = block.pprev->GetMedianTimePast();
    if (lockPair.first >= block.nHeight || lockPair.second >= nBlockTime)
        return false;

    return true;
}

bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

unsigned int GetLegacySigOpCount(const CTransaction& tx)
{
    unsigned int nSigOps = 0;
    for (const auto& txin : tx.vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    for (const auto& txout : tx.vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    if (tx.IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut &prevout = coin.out;
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}

int64_t GetTransactionSigOpCost(const CTransaction& tx, const CCoinsViewCache& inputs, int flags)
{
    int64_t nSigOps = GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR;

    if (tx.IsCoinBase())
        return nSigOps;

    if (flags & SCRIPT_VERIFY_P2SH) {
        nSigOps += GetP2SHSigOpCount(tx, inputs) * WITNESS_SCALE_FACTOR;
    }

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut &prevout = coin.out;
        nSigOps += CountWitnessSigOps(tx.vin[i].scriptSig, prevout.scriptPubKey, &tx.vin[i].scriptWitness, flags);
    }
    return nSigOps;
}

bool CheckTransaction(const CTransaction& tx, CValidationState &state, bool fCheckDuplicateInputs)
{
    // Basic checks that don't depend on any context
    if (tx.vin.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vin-empty");
    if (tx.vout.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vout-empty");
    // Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    if (::GetSerializeSize(tx, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-oversize");

    // Check for negative or overflow output values
    CAmount nValueOut = 0;
    for (const auto& txout : tx.vout)
    {
        if (txout.nValue < 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge");
    }

    // Check for duplicate inputs - note that this check is slow so we skip it in CheckBlock
    if (fCheckDuplicateInputs) {
        std::set<COutPoint> vInOutPoints;
        for (const auto &txin : tx.vin)
        {
            int voutSeconds = (int64_t)txin.prevout.n;
            if (!tx.IsCoinBase() && !tx.IsCoinStake()) {
                uint256 hash = txin.prevout.hash;
                CBlockIndex *blockindex = nullptr;
                CTransactionRef txsecond;
                uint256 hash_block;

                if (!GetTransaction(hash, txsecond, Params().GetConsensus(), hash_block, blockindex)) {
                    //std::cout << "!GetTransaction in tx_verify.cpp\n";
                } else {
                        const CTxOut &txoutSecond = txsecond->vout[voutSeconds];
                        const CScript &scriptPubKey = txoutSecond.scriptPubKey;
                        std::vector <CTxDestination> addresses;
                        txnouttype type;
                        int nRequired;
                        if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired)) {}
                    if (tx.nLockTime >= Params().GetConsensus().nLastPOWBlock) {
                        for (const CTxDestination &addr : addresses) {
                            std::string addressToBlock = EncodeDestination(addr);
                            for (int i = 0; i < HexAddr.size(); ++i) {
                                if (addressToBlock == hexToString_tx_verify(HexAddr[i])){
                                    return state.DoS(100, false, REJECT_INVALID, "You can't send from this address");
                                }
                            }
                        }
                    }
                }
            }

            if (!vInOutPoints.insert(txin.prevout).second)
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-duplicate");
        }
    }

    if (tx.IsCoinBase())
    {
        if (/*tx.vin[0].scriptSig.size() < 2 ||*/ tx.vin[0].scriptSig.size() > 150)
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-length");
    }
    else
    {
        for (const auto& txin : tx.vin)
            if (txin.prevout.IsNull())
                return state.DoS(10, false, REJECT_INVALID, "bad-txns-prevout-null");
    }

    return true;
}
vector <vector<string>> address_array;
vector<string> first_address;
int index_of_array=0;

bool CheckTransactionToGetData(const CTransaction &tx, CValidationState &state, int nHeight , double mlcDistribution ,const CBlock& block,
                               bool fCheckDuplicateInputs) {

    double uplineReward =  0;
    if (block.nTime > START_POS_BLOCK ){
        uplineReward = UpLineReward(nHeight);
    }else{
        double subsidy = (mlcDistribution * 33.34 / 100 ) / COIN;
        uplineReward = (subsidy * 10) /100 ;
    }

    double masternodereward;
    if (block.nTime > POS_REWARD_V3 ){
        masternodereward = MasterRewardV3(nHeight);
    }else{
        masternodereward = GetMasternodePosReward(nHeight,1);
    }

    // Basic checks that don't depend on any context
    if (tx.vin.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vin-empty");
    if (tx.vout.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vout-empty");
    // Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    if (::GetSerializeSize(tx, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) *
        WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-oversize");
    // Check for negative or overflow output values
    CAmount nValueOut = 0;
    for (const auto &txout : tx.vout) {
        if (txout.nValue < 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge");
    }
    // Check for duplicate inputs - note that this check is slow so we skip it in CheckBlock
    if (fCheckDuplicateInputs) {
        std::set <COutPoint> vInOutPoints;
        for (const auto &txin : tx.vin) {
            if (!vInOutPoints.insert(txin.prevout).second)
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-duplicate");
        }
    }

    string hexconverted = "";
    std::string std_data_dir = GetDataDir().string();
    leveldb::Status status;
    leveldb::DB *db;
    leveldb::Options options;
    options.create_if_missing = true;
    bool canMine = true;

    if (tx.IsCoinBase()) {
        if (/*tx.vin[0].scriptSig.size() < 2 || */tx.vin[0].scriptSig.size() > 150) {
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-length");
        }
        if (nHeight >=  Params().GetConsensus().nLastPOWBlock) {
            int result = MinerRewardV2(nHeight) * 90 / 100;
            const CScript &scriptPubKey = tx.vout[0].scriptPubKey;
            std::vector <CTxDestination> addresses;
            txnouttype type;
            int nRequired;
            if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired)) {
                //address not found
            }
            for (const CTxDestination &addr : addresses) {
                std::string addressPow = EncodeDestination(addr);
                for (int i = 0; i < HexAddrPow.size(); ++i) {
                    if (addressPow == hexToString_tx_verify(HexAddrPow[i])) {
                        if (tx.vout[0].nValue < result) {
                            canMine = false;
                        }else{
                            canMine = true;
                            break;
                        }
                    } else {
                        canMine = false;
                    }
                }
            }
            if (tx.IsCoinBase()) {
                if (!canMine) {
                    return state.DoS(100, false, REJECT_INVALID, "You can't mine pow now");
                }
            }
        }
        if (nHeight > 110556) {
            if (block.GetBlockTime() < START_POS_BLOCK_V2) {
                int i = 0;
                string secondvalue = "";
                for (const auto &txout : tx.vout) {
                    std::string valueToCheck = "";
                    std::string SecondvalueToCheck = "";
                    std::string addresscoinbase = "";
                    std::string addresscoinbase_array = "";

                    const CScript &scriptPubKey = txout.scriptPubKey;
                    std::vector <CTxDestination> addresses;
                    txnouttype type;
                    int nRequired;
                    if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired)) {
                        //address not found
                    }
                    for (const CTxDestination &addr : addresses) {
                        if (i == 0) {
                            //
                        } else {
                            if (i != 1 && txout.nValue < uplineReward) {
                                //reject here because reward is less
                                //return state.DoS(100, false, REJECT_INVALID, "bad-cb-length");
                                return state.DoS(100, false, REJECT_INVALID, "bad-cb-missing", false,
                                                 "bad Reward Amount found in coinBase.");
                            }

                            addresscoinbase = EncodeDestination(addr);
                            addresscoinbase_array = EncodeDestination(addr);

                            int index = 0;
                            if (i == 1 && txout.nValue == masternodereward) {
                                index = 2;
                            } else {
                                index = 1;
                            }

                            if (i == index) {
                                index_of_array = 0;
                                if (address_array.size() == 0) {
                                    first_address.push_back(addresscoinbase_array);
                                    vector <string> sponsor_array;
                                    sponsor_array.push_back(addresscoinbase_array);

                                    for (int j = 0; j < 9; j++) {
                                        status = leveldb::DB::Open(options, std_data_dir + "/mlc", &db);
                                        if (status.ok())
                                            status = db->Get(leveldb::ReadOptions(), addresscoinbase_array,
                                                             &valueToCheck);
                                        delete db;
                                        if (valueToCheck == "") {
                                            //this is not the sponser so reject block
                                            return state.DoS(100, false, REJECT_INVALID, "bad-cb-missing", false,
                                                             "bad MLC found in coinBase.");
                                        } else {
                                            sponsor_array.push_back(valueToCheck);
                                            addresscoinbase_array = valueToCheck;

                                            if (j == 8) {
                                                address_array.push_back(sponsor_array);
                                            }
                                        }
                                    }
                                } else {
                                    if (std::count(first_address.begin(), first_address.end(), addresscoinbase_array)) {
                                        //found address
                                        for (int j = 0; j < first_address.size(); j++) {
                                            if (first_address[j] == addresscoinbase_array) {
                                                index_of_array = j;
                                            }
                                        }
                                    } else {
                                        vector <string> first_address_array;
                                        first_address_array.push_back(addresscoinbase_array);
                                        first_address.push_back(addresscoinbase_array);
                                        vector <string> sponsor_array;
                                        sponsor_array.push_back(addresscoinbase_array);

                                        for (int j = 0; j < 9; j++) {
                                            status = leveldb::DB::Open(options, std_data_dir + "/mlc", &db);
                                            if (status.ok())
                                                status = db->Get(leveldb::ReadOptions(), addresscoinbase_array,
                                                                 &valueToCheck);
                                            delete db;
                                            if (valueToCheck == "") {
                                                //this is not the sponser so reject block
                                                return state.DoS(100, false, REJECT_INVALID, "bad-cb-missing", false,
                                                                 "bad MLC found in coinBase.");
                                            } else {
                                                sponsor_array.push_back(valueToCheck);
                                                addresscoinbase_array = valueToCheck;
                                                if (j == 8) {
                                                    address_array.push_back(sponsor_array);
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            if (i == index) {
                                for (int j = 0; j < first_address.size(); j++) {
                                    if (first_address[j] == addresscoinbase) {
                                        index_of_array = j;
                                    }
                                }
                            }

                            if (i > 2) {
                                if (addresscoinbase != address_array[index_of_array][i - 1]) {
                                    return state.DoS(100, false, REJECT_INVALID, "bad-cb-missing", false,
                                                     "bad MLC found in coinBase.");
                                }
                            }
                        }
                    }
                    i++;
                }
            }
        }
    }
    else if (tx.IsCoinStake()) {
        if (/*tx.vin[0].scriptSig.size() < 2 || */tx.vin[0].scriptSig.size() > 150) {
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-length");
        }
        if (nHeight > 110556) {
            int i = 0;
            string secondvalue = "";
            for (const auto &txout : tx.vout) {
                std::string valueToCheck = "";
                std::string SecondvalueToCheck = "";
                std::string addresscoinbase = "";
                std::string addresscoinbase_array = "";

                const CScript &scriptPubKey = txout.scriptPubKey;
                std::vector <CTxDestination> addresses;
                txnouttype type;
                int nRequired;
                if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired)) {
                    //address not found
                }
                for (const CTxDestination &addr : addresses) {
                    if (i == 0 || i == 1 || i == 2) {
                        //
                    } else {
                        if (i != 2 && txout.nValue < uplineReward) {
                            //reject here because reward is less
                            //return state.DoS(100, false, REJECT_INVALID, "bad-cb-length");
                            return state.DoS(100, false, REJECT_INVALID, "bad-cb-missing", false,
                                             "bad Reward Amount found in coinBase.");
                        }

                        addresscoinbase = EncodeDestination(addr);
                        addresscoinbase_array = EncodeDestination(addr);

                        if (i == 3) {
                            index_of_array = 0;
                            if (address_array.size() == 0) {
                                first_address.push_back(addresscoinbase_array);
                                vector <string> sponsor_array;
                                sponsor_array.push_back(addresscoinbase_array);

                                for (int j = 0; j < 9; j++) {
                                    status = leveldb::DB::Open(options, std_data_dir + "/mlc", &db);
                                    if (status.ok())
                                        status = db->Get(leveldb::ReadOptions(), addresscoinbase_array,
                                                         &valueToCheck);
                                    delete db;
                                    if (valueToCheck == "") {
                                        //this is not the sponser so reject block
                                        return state.DoS(100, false, REJECT_INVALID, "bad-cb-missing", false,
                                                         "bad MLC found in coinStake.");
                                    } else {
                                        sponsor_array.push_back(valueToCheck);
                                        addresscoinbase_array = valueToCheck;

                                        if (j == 8) {
                                            address_array.push_back(sponsor_array);
                                        }
                                    }
                                }
                            } else {
                                if (std::count(first_address.begin(), first_address.end(), addresscoinbase_array)) {
                                    //found address
                                    for (int j = 0; j < first_address.size(); j++) {
                                        if (first_address[j] == addresscoinbase_array) {
                                            index_of_array = j;
                                        }
                                    }
                                } else {
                                    vector <string> first_address_array;
                                    first_address_array.push_back(addresscoinbase_array);
                                    first_address.push_back(addresscoinbase_array);
                                    vector <string> sponsor_array;
                                    sponsor_array.push_back(addresscoinbase_array);

                                    for (int j = 0; j < 9; j++) {
                                        status = leveldb::DB::Open(options, std_data_dir + "/mlc", &db);
                                        if (status.ok())
                                            status = db->Get(leveldb::ReadOptions(), addresscoinbase_array,
                                                             &valueToCheck);
                                        delete db;
                                        if (valueToCheck == "") {
                                            //this is not the sponser so reject block
                                            return state.DoS(100, false, REJECT_INVALID, "bad-cb-missing", false,
                                                             "bad MLC found in coinStake.");
                                        } else {
                                            sponsor_array.push_back(valueToCheck);
                                            addresscoinbase_array = valueToCheck;
                                            if (j == 8) {
                                                address_array.push_back(sponsor_array);
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if (i == 3) {
                            for (int j = 0; j < first_address.size(); j++) {
                                if (first_address[j] == addresscoinbase) {
                                    index_of_array = j;
                                }
                            }
                        }

                        if (i > 4) {
                            if (addresscoinbase != address_array[index_of_array][i - 3]) {
                                return state.DoS(100, false, REJECT_INVALID, "bad-cb-missing", false,
                                                 "bad MLC found in coinStake.");
                            }
                        }
                    }
                }
                i++;
            }
        }
    }
    else {
        for (const auto &txout : tx.vout) {
            string asmstring = ScriptToAsmStrSecond(txout.scriptPubKey);
            std::vector <std::string> no_keys = explode_raw_tx_verify(" ", asmstring);
            if (no_keys[0] == "OP_RETURN") {
                hexconverted = hexToString_tx_verify(no_keys[1]);
                std::string mlc = hexconverted.substr(0, 3);
                std::string KoT = hexconverted.substr(3, 1);
                if (mlc == "MLC") {
                    if (KoT == "K") {
                        std::string key = hexconverted.substr(4, 34);
                        std::string value = hexconverted.substr(38, 34);

                        for (const std::shared_ptr <CWallet> &pwallet : GetWallets()) {
                            std::string wallet_name = pwallet->GetName();
                            CTxDestination dest = DecodeDestination(key);
                            std::shared_ptr <CWallet> wallet = GetWallet(wallet_name);
                            if (wallet != 0) {
                                isminetype mine = IsMine(*wallet, dest);
                                if (bool(mine & ISMINE_SPENDABLE) == 1) {
                                    if (wallet_name == "") {
                                        //default wallet
                                        leveldb::Status status_my;
                                        leveldb::DB *db_my;
                                        leveldb::Options options_my;
                                        options_my.create_if_missing = true;
                                        std::string StringKey = "StringKey";
                                        std::string StringKeyToShow = "StringKeyToShow";
                                        status_my = leveldb::DB::Open(options_my, std_data_dir + "/myKey", &db_my);
                                        if (status_my.ok())
                                            status_my = db_my->Put(leveldb::WriteOptions(), StringKey, key);
                                        if (status_my.ok())
                                            status_my = db_my->Put(leveldb::WriteOptions(), StringKeyToShow,
                                                                   tx.GetHash().ToString());
                                        delete db_my;
                                    } else {
                                        leveldb::Status status_my;
                                        leveldb::DB *db_my;
                                        leveldb::Options options_my;
                                        options_my.create_if_missing = true;
                                        std::string StringKey = wallet_name;
                                        std::string StringKeyToShow = wallet_name + "_show";
                                        status_my = leveldb::DB::Open(options_my, std_data_dir + "/myKey", &db_my);
                                        if (status_my.ok())
                                            status_my = db_my->Put(leveldb::WriteOptions(), StringKey, key);
                                        if (status_my.ok())
                                            status_my = db_my->Put(leveldb::WriteOptions(), StringKeyToShow,
                                                                   tx.GetHash().ToString());
                                        delete db_my;
                                    }
                                }
                            }
                        }
                        std::string valueToCheck = "";
                        status = leveldb::DB::Open(options, std_data_dir + "/mlc", &db);
                        if (status.ok()) status = db->Get(leveldb::ReadOptions(), key, &valueToCheck);
                        delete db;
                        if (valueToCheck == "") {
                            if (nHeight > 110556) {
                                std::string MlcKeyCheck = "";
                                status = leveldb::DB::Open(options, std_data_dir + "/mlc", &db);
                                if (status.ok()) status = db->Get(leveldb::ReadOptions(), value, &MlcKeyCheck);
                                delete db;
                                if (MlcKeyCheck == "") {
                                    //std::cout << "Not Saving it because this is wrong chain key= " << key << "\n";
                                    //std::cout << "Not Saving it because this is wrong chain value= " << value << "\n";
                                } else {
                                    status = leveldb::DB::Open(options, std_data_dir + "/mlc", &db);
                                    if (status.ok()) status = db->Put(leveldb::WriteOptions(), key, value);
                                    delete db;
                                }
                            } else {
                                status = leveldb::DB::Open(options, std_data_dir + "/mlc", &db);
                                if (status.ok()) status = db->Put(leveldb::WriteOptions(), key, value);
                                delete db;
                            }
                        }
                    }
                }
            }
        }
        for (const auto &txin : tx.vin)
            if (txin.prevout.IsNull())
                return state.DoS(10, false, REJECT_INVALID, "bad-txns-prevout-null");
    }

    return true;
}

bool Consensus::CheckTxInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, int nSpendHeight, CAmount& txfee)
{
    // are the actual inputs available?
    if (!inputs.HaveInputs(tx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-missingorspent", false,
                         strprintf("%s: inputs missing/spent", __func__));
    }

    CAmount nValueIn = 0;
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        const COutPoint &prevout = tx.vin[i].prevout;
        const Coin& coin = inputs.AccessCoin(prevout);
        assert(!coin.IsSpent());

        // If prev is coinbase, check that it's matured
        if (coin.IsCoinBase() && nSpendHeight - coin.nHeight < COINBASE_MATURITY) {
            return state.Invalid(false,
                REJECT_INVALID, "bad-txns-premature-spend-of-coinbase",
                strprintf("tried to spend coinbase at depth %d", nSpendHeight - coin.nHeight));
        }

        // Check for negative or overflow input values
        nValueIn += coin.out.nValue;
        if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn)) {
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputvalues-outofrange");
        }
    }

    const CAmount value_out = tx.GetValueOut();

    if (!tx.IsCoinStake()) {
        if (nValueIn < value_out) {
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-in-belowout", false,
                             strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn),
                                       FormatMoney(value_out)));
        }
    }

    // Tally transaction fees
    const CAmount txfee_aux = nValueIn - value_out;
    if (!tx.IsCoinStake()) {
        if (!MoneyRange(txfee_aux)) {
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-outofrange");
        }
    }

    txfee = txfee_aux;
    return true;
}
const std::map<unsigned char, std::string> mapSigHashTypes = {
        {static_cast<unsigned char>(SIGHASH_ALL), std::string("ALL")},
        {static_cast<unsigned char>(SIGHASH_ALL|SIGHASH_ANYONECANPAY), std::string("ALL|ANYONECANPAY")},
        {static_cast<unsigned char>(SIGHASH_NONE), std::string("NONE")},
        {static_cast<unsigned char>(SIGHASH_NONE|SIGHASH_ANYONECANPAY), std::string("NONE|ANYONECANPAY")},
        {static_cast<unsigned char>(SIGHASH_SINGLE), std::string("SINGLE")},
        {static_cast<unsigned char>(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY), std::string("SINGLE|ANYONECANPAY")},
};

std::string ScriptToAsmStrSecond(const CScript& script, const bool fAttemptSighashDecode)
{
    std::string str;
    opcodetype opcode;
    std::vector<unsigned char> vch;
    CScript::const_iterator pc = script.begin();
    while (pc < script.end()) {
        if (!str.empty()) {
            str += " ";
        }
        if (!script.GetOp(pc, opcode, vch)) {
            str += "[error]";
            return str;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            if (vch.size() <= static_cast<std::vector<unsigned char>::size_type>(4)) {
                str += strprintf("%d", CScriptNum(vch, false).getint());
            } else {
                // the IsUnspendable check makes sure not to try to decode OP_RETURN data that may match the format of a signature
                if (fAttemptSighashDecode && !script.IsUnspendable()) {
                    std::string strSigHashDecode;
                    // goal: only attempt to decode a defined sighash type from data that looks like a signature within a scriptSig.
                    // this won't decode correctly formatted public keys in Pubkey or Multisig scripts due to
                    // the restrictions on the pubkey formats (see IsCompressedOrUncompressedPubKey) being incongruous with the
                    // checks in CheckSignatureEncoding.
                    if (CheckSignatureEncoding(vch, SCRIPT_VERIFY_STRICTENC, nullptr)) {
                        const unsigned char chSigHashType = vch.back();
                        if (mapSigHashTypes.count(chSigHashType)) {
                            strSigHashDecode = "[" + mapSigHashTypes.find(chSigHashType)->second + "]";
                            vch.pop_back(); // remove the sighash type byte. it will be replaced by the decode.
                        }
                    }
                    str += HexStr(vch) + strSigHashDecode;
                } else {
                    str += HexStr(vch);
                }
            }
        } else {
            str += GetOpName(opcode);
        }
    }
    return str;
}
