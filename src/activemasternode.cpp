// Copyright (c) 2012-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The Luxcore developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "protocol.h"
#include "activemasternode.h"
#include <boost/lexical_cast.hpp>
#include "key_io.h"

#include "netmessagemaker.h"

#include <consensus/validation.h>
#include <net.h>
#include <txmempool.h>
#include <validation.h>
#include <validationinterface.h>
#include <node/transaction.h>
#include "init.h"
#include <future>
#include "net_processing.h"

//
// Bootup the masternode, look for a 10000 Xlt input and register on the network
//

void CActiveMasternode::ManageStatus(CConnman* connman) {
    std::string errorMessage;

    if (!fMasterNode) return;

    if (fDebug) LogPrintf("CActiveMasternode::ManageStatus() - Begin\n");

    //need correct adjusted time to send ping
    bool fIsInitialDownload = IsInitialBlockDownload();
    if (fIsInitialDownload) {
        status = MASTERNODE_SYNC_IN_PROCESS;
        LogPrintf("CActiveMasternode::ManageStatus() - Sync in progress. Must wait until sync is complete to start masternode.\n");
        return;
    }

    if (status == MASTERNODE_INPUT_TOO_NEW || status == MASTERNODE_NOT_CAPABLE || status == MASTERNODE_SYNC_IN_PROCESS) {
        status = MASTERNODE_NOT_PROCESSED;
    }

    if (status == MASTERNODE_NOT_PROCESSED) {
        if (strMasterNodeAddr.empty()) {
            if (!GetLocal(service)) {
                notCapableReason = "Can't detect external address. Please use the masternodeaddr configuration option.";
                status = MASTERNODE_NOT_CAPABLE;
                LogPrintf("CActiveMasternode::ManageStatus() - not capable: %s\n", notCapableReason.c_str());
                return;
            }
        } else {
            service = CService(strMasterNodeAddr,true);
        }

        LogPrintf("CActiveMasternode::ManageStatus() - Checking inbound connection to '%s'\n", service.ToString().c_str());

        const char *pszDest =  service.ToString().c_str();
        CAddress addrConnect = CAddress(service, NODE_NETWORK);

        if (!connman->ConnectNode(addrConnect, pszDest,true,true)) {
             notCapableReason = "Could not connect to " + service.ToString();
             status = MASTERNODE_NOT_CAPABLE;
             LogPrintf("CActiveMasternode::ManageStatus() - not capable: %s\n", notCapableReason.c_str());
             return;
         }

        std::string wallet_name = "";
        std::shared_ptr<CWallet> pwallet = GetWallet(wallet_name);
        if (pwallet->IsLocked()) {
            notCapableReason = "Wallet is locked.";
            status = MASTERNODE_NOT_CAPABLE;
            LogPrintf("CActiveMasternode::ManageStatus() - not capable: %s\n", notCapableReason.c_str());
            return;
        }


        // Set defaults
        status = MASTERNODE_NOT_CAPABLE;
        notCapableReason = "Unknown. Check debug.log for more information.\n";

        // Choose coins to use
        CPubKey pubKeyCollateralAddress;
        CKey keyCollateralAddress;

        if (GetMasterNodeVin(vin, pubKeyCollateralAddress, keyCollateralAddress)) {
            if (GetInputAge(vin) < MASTERNODE_MIN_CONFIRMATIONS) {
                LogPrintf("CActiveMasternode::ManageStatus() - Input must have least %d confirmations - %d confirmations\n", MASTERNODE_MIN_CONFIRMATIONS, GetInputAge(vin));
                status = MASTERNODE_INPUT_TOO_NEW;
                return;
            }

            LogPrintf("CActiveMasternode::ManageStatus() - Is capable master node!\n");

            status = MASTERNODE_IS_CAPABLE;
            notCapableReason = "";

            pwallet->LockCoin(vin.prevout);

            // send to all nodes
            CPubKey pubKeyMasternode;
            CKey keyMasternode;

            if (!darkSendSigner.SetKey(strMasterNodePrivKey, errorMessage, keyMasternode, pubKeyMasternode)) {
                LogPrintf("Register::ManageStatus() - Error upon calling SetKey: %s\n", errorMessage.c_str());
                return;
            }

            if (!Register(connman, vin, service, keyCollateralAddress, pubKeyCollateralAddress, keyMasternode, pubKeyMasternode, errorMessage)) {
                LogPrintf("CActiveMasternode::ManageStatus() - Error on Register: %s\n", errorMessage.c_str());
            }

            return;
        } else {
            LogPrintf("CActiveMasternode::ManageStatus() - Could not find suitable coins!\n");
        }
    }
    //send to all peers
    if (!Dseep(connman, errorMessage)) {
        LogPrintf("CActiveMasternode::ManageStatus() - Error on Ping: %s", errorMessage.c_str());
    }
}

// Send stop dseep to network for remote masternode
bool CActiveMasternode::StopMasterNode(CConnman* connman ,std::string strService,std::string strColletralAddress, std::string strKeyMasternode, std::string& errorMessage) {
    CTxIn vin;
    CKey keyMasternode;
    CPubKey pubKeyMasternode;

    if (!darkSendSigner.SetKey(strKeyMasternode, errorMessage, keyMasternode, pubKeyMasternode)) {
        LogPrintf("CActiveMasternode::StopMasterNode() - Error: %s\n", errorMessage.c_str());
        return false;
    }

    if (!GetMasterNodeVinForPubKey(strColletralAddress, vin, pubKeyMasternode, keyMasternode)) {
        errorMessage = "could not allocate vin for collateralAddress";
        LogPrintf("Register::Register() - Error: %s\n", errorMessage.c_str());
        return false;
    }

    return StopMasterNode(connman,vin, CService(strService), keyMasternode, pubKeyMasternode, errorMessage);
}

// Send stop dseep to network for main masternode
bool CActiveMasternode::StopMasterNode(CConnman* connman, std::string& errorMessage) {
    if (status != MASTERNODE_IS_CAPABLE && status != MASTERNODE_REMOTELY_ENABLED) {
        errorMessage = "masternode is not in a running status";
        LogPrintf("CActiveMasternode::StopMasterNode() - Error: %s\n", errorMessage.c_str());
        return false;
    }

    status = MASTERNODE_STOPPED;
    CPubKey pubKeyMasternode;
    CKey keyMasternode;

    if (!darkSendSigner.SetKey(strMasterNodePrivKey, errorMessage, keyMasternode, pubKeyMasternode)) {
        LogPrintf("Register::ManageStatus() - Error upon calling SetKey: %s\n", errorMessage.c_str());
        return false;
    }

    return StopMasterNode(connman,vin, service, keyMasternode, pubKeyMasternode, errorMessage);
}

// Send stop dseep to network for any masternode
bool CActiveMasternode::StopMasterNode(CConnman* connman, CTxIn vin, CService service, CKey keyMasternode, CPubKey pubKeyMasternode, std::string& errorMessage) {
    std::string wallet_name = "";
    std::shared_ptr<CWallet> pwallet = GetWallet(wallet_name);
    pwallet->UnlockCoin(vin.prevout);
    return Dseep(connman, vin, service, keyMasternode, pubKeyMasternode, errorMessage, true);
}

bool CActiveMasternode::Dseep(CConnman* connman, std::string& errorMessage) {
    if (status != MASTERNODE_IS_CAPABLE && status != MASTERNODE_REMOTELY_ENABLED) {
        errorMessage = "masternode is not in a running status";
        LogPrintf("CActiveMasternode::Dseep() - Error: %s\n", errorMessage.c_str());
        return false;
    }

    CPubKey pubKeyMasternode;
    CKey keyMasternode;

    if (!darkSendSigner.SetKey(strMasterNodePrivKey, errorMessage, keyMasternode, pubKeyMasternode)) {
        LogPrintf("Register::ManageStatus() - Error upon calling SetKey: %s\n", errorMessage.c_str());
        return false;
    }

    return Dseep(connman,vin, service, keyMasternode, pubKeyMasternode, errorMessage, false);
}

bool CActiveMasternode::Dseep(CConnman* connman, CTxIn vin, CService service, CKey keyMasternode, CPubKey pubKeyMasternode, std::string& retErrorMessage, bool stop) {
    std::string errorMessage;
    std::vector<unsigned char> vchMasterNodeSignature;
    std::string strMasterNodeSignMessage;
    int64_t masterNodeSignatureTime = GetAdjustedTime();

    std::string strMessage = service.ToString() + boost::lexical_cast<std::string>(masterNodeSignatureTime) + boost::lexical_cast<std::string>(stop);

    if (!darkSendSigner.SignMessage(strMessage, errorMessage, vchMasterNodeSignature, keyMasternode)) {
        retErrorMessage = "sign message failed: " + errorMessage;
        LogPrintf("CActiveMasternode::Dseep() - Error: %s\n", retErrorMessage.c_str());
        return false;
    }

    if (!darkSendSigner.VerifyMessage(pubKeyMasternode, vchMasterNodeSignature, strMessage, errorMessage)) {
        retErrorMessage = "Verify message failed: " + errorMessage;
        LogPrintf("CActiveMasternode::Dseep() - Error: %s\n", retErrorMessage.c_str());
        return false;
    }

    // Update Last Seen timestamp in masternode list
    bool found = false;
    for (CMasterNode& mn : vecMasternodes) {
        
        if (mn.vin == vin) {
            found = true;
            mn.UpdateLastSeen();
        }
    }

    if (!found) {
        // Seems like we are trying to send a ping while the masternode is not registered in the network
        retErrorMessage = "Darksend Masternode List doesn't include our masternode, Shutting down masternode pinging service! " + vin.ToString();
        LogPrintf("CActiveMasternode::Dseep() - Error: %s\n", retErrorMessage.c_str());
        status = MASTERNODE_NOT_CAPABLE;
        notCapableReason = retErrorMessage;
        return false;
    }

    //send to all peers
    LogPrintf("CActiveMasternode::Dseep() - SendDarkSendElectionEntryPing vin = %s\n", vin.ToString().c_str());
    connman->SendDarkSendElectionEntryPing(vin, vchMasterNodeSignature, masterNodeSignatureTime, stop);
    return true;
}

bool CActiveMasternode::RegisterByPubKey(CConnman *connman, std::string strService, std::string strKeyMasternode, std::string collateralAddress, std::string& errorMessage) {
    CTxIn vin;
    CPubKey pubKeyCollateralAddress;
    CKey keyCollateralAddress;
    CPubKey pubKeyMasternode;
    CKey keyMasternode;

    if (!darkSendSigner.SetKey(strKeyMasternode, errorMessage, keyMasternode, pubKeyMasternode)) {
        LogPrintf("CActiveMasternode::RegisterByPubKey() - Error upon calling SetKey: %s\n", errorMessage.c_str());
        return false;
    }

    if (!GetMasterNodeVinForPubKey(collateralAddress, vin, pubKeyCollateralAddress, keyCollateralAddress)) {
        errorMessage = "could not allocate vin for collateralAddress";
        LogPrintf("Register::Register() - Error: %s\n", errorMessage.c_str());
        return false;
    }

    //std::string errorMessage;
    std::vector<unsigned char> vchMasterNodeSignature;
    //std::string strMasterNodeSignMessage;
    int64_t masterNodeSignatureTime = GetAdjustedTime();

    std::string vchPubKey(pubKeyCollateralAddress.begin(), pubKeyCollateralAddress.end());
    std::string vchPubKey2(pubKeyMasternode.begin(), pubKeyMasternode.end());

    std::string strMessage = strService + boost::lexical_cast<std::string>(masterNodeSignatureTime) + vchPubKey + vchPubKey2 + boost::lexical_cast<std::string>(PROTOCOL_VERSION);

    if (!darkSendSigner.SignMessage(strMessage, errorMessage, vchMasterNodeSignature, keyCollateralAddress)) {
        errorMessage = "sign message failed: " + errorMessage;
        LogPrintf("CActiveMasternode::Register() - Error: %s\n", errorMessage.c_str());
        return false;
    }

    if (!darkSendSigner.VerifyMessage(pubKeyCollateralAddress, vchMasterNodeSignature, strMessage, errorMessage)) {
        errorMessage = "Verify message failed: " + errorMessage;
        LogPrintf("CActiveMasternode::Register() - Error: %s\n", errorMessage.c_str());
        return false;
    }

    bool found = false;
    LOCK(cs_masternodes);
    for (CMasterNode& mn : vecMasternodes)
        if (mn.vin == vin)
            found = true;

    if (!found) {
        LogPrintf("CActiveMasternode::Register() - Adding to masternode list service: %s - vin: %s\n", strService, vin.ToString().c_str());
        CMasterNode mn(CService(strService), vin, pubKeyCollateralAddress, vchMasterNodeSignature, masterNodeSignatureTime, pubKeyMasternode,
                       PROTOCOL_VERSION);
        mn.UpdateLastSeen(masterNodeSignatureTime);
        vecMasternodes.push_back(mn);
    }

    std::vector<CNode*> vNodesCopy;
    {
        LOCK(connman->cs_vNodes);
        vNodesCopy = connman->vNodes;
    }
    const CNetMsgMaker msgMaker(PROTOCOL_VERSION);
    for (CNode* pnode : vNodesCopy) {
        //std::cout << "in for loop pnode in net.cpp\n";
        if (pnode) {
            connman->PushMessage(pnode, msgMaker.Make("dsee", vin, CService(strService), vchMasterNodeSignature, masterNodeSignatureTime,
                                                      pubKeyCollateralAddress, pubKeyMasternode, -1, -1, masterNodeSignatureTime,
                                                                              PROTOCOL_VERSION));
        }
    }

    return Register(connman, vin, CService(strService), keyCollateralAddress, pubKeyCollateralAddress, keyMasternode, pubKeyMasternode, errorMessage);
    //return true;
}

bool CActiveMasternode::Register(CConnman* connman ,std::string strService, std::string strKeyMasternode, std::string txHash, std::string strOutputIndex, std::string& errorMessage) {
    CTxIn vin;
    CPubKey pubKeyCollateralAddress;
    CKey keyCollateralAddress;
    CPubKey pubKeyMasternode;
    CKey keyMasternode;

    if (!darkSendSigner.SetKey(strKeyMasternode, errorMessage, keyMasternode, pubKeyMasternode)) {
        LogPrintf("CActiveMasternode::Register() - Error upon calling SetKey: %s\n", errorMessage.c_str());
        return false;
    }

    if (!GetMasterNodeVin(vin, pubKeyCollateralAddress, keyCollateralAddress, txHash, strOutputIndex)) {
        errorMessage = "could not allocate vin";
        LogPrintf("Register::Register() - Error: %s\n", errorMessage.c_str());
        return false;
    }
    return Register(connman, vin, CService(strService), keyCollateralAddress, pubKeyCollateralAddress, keyMasternode, pubKeyMasternode, errorMessage);
}

bool CActiveMasternode::Register(CConnman* connman, CTxIn vin, CService service, CKey keyCollateralAddress, CPubKey pubKeyCollateralAddress, CKey keyMasternode, CPubKey pubKeyMasternode, std::string& retErrorMessage) {
    std::string errorMessage;
    std::vector<unsigned char> vchMasterNodeSignature;
    std::string strMasterNodeSignMessage;
    int64_t masterNodeSignatureTime = GetAdjustedTime();


    std::string vchPubKey(pubKeyCollateralAddress.begin(), pubKeyCollateralAddress.end());
    std::string vchPubKey2(pubKeyMasternode.begin(), pubKeyMasternode.end());

    std::string strMessage = service.ToString() + boost::lexical_cast<std::string>(masterNodeSignatureTime) + vchPubKey + vchPubKey2 + boost::lexical_cast<std::string>(PROTOCOL_VERSION);


    if (!darkSendSigner.SignMessage(strMessage, errorMessage, vchMasterNodeSignature, keyCollateralAddress)) {
        retErrorMessage = "sign message failed: " + errorMessage;
        LogPrintf("CActiveMasternode::Register() - Error: %s\n", retErrorMessage.c_str());
        return false;
    }

    if (!darkSendSigner.VerifyMessage(pubKeyCollateralAddress, vchMasterNodeSignature, strMessage, errorMessage)) {
        retErrorMessage = "Verify message failed: " + errorMessage;
        LogPrintf("CActiveMasternode::Register() - Error: %s\n", retErrorMessage.c_str());
        return false;
    }

    bool found = false;
    LOCK(cs_masternodes);
    for (CMasterNode& mn : vecMasternodes)
        if (mn.vin == vin)
            found = true;

    if (!found) {
        LogPrintf("CActiveMasternode::Register() - Adding to masternode list service: %s - vin: %s\n", service.ToString().c_str(), vin.ToString().c_str());
        CMasterNode mn(service, vin, pubKeyCollateralAddress, vchMasterNodeSignature, masterNodeSignatureTime, pubKeyMasternode, PROTOCOL_VERSION);
        mn.UpdateLastSeen(masterNodeSignatureTime);
        vecMasternodes.push_back(mn);
    }

    //send to all peers
    LogPrintf("CActiveMasternode::Register() - SendDarkSendElectionEntry vin = %s\n", vin.ToString().c_str());

    connman->SendDarkSendElectionEntry(vin, service, vchMasterNodeSignature, masterNodeSignatureTime, pubKeyCollateralAddress, pubKeyMasternode, -1, -1, masterNodeSignatureTime, PROTOCOL_VERSION);
    return true;
}

bool CActiveMasternode::GetMasterNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey) {
    return GetMasterNodeVin(vin, pubkey, secretKey, "", "");
}

bool CActiveMasternode::GetMasterNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey, std::string strTxHash, std::string strOutputIndex) {
    CScript pubScript;

    // Find possible candidates
    vector <COutput> possibleCoins = SelectCoinsMasternode();
    COutput* selectedOutput;

    // Find the vin
    if (!strTxHash.empty()) {
        // Let's find it
        arith_uint256 txHash(strTxHash);
        int outputIndex = 0;
        try
        {
            outputIndex = std::stoi(strOutputIndex.c_str());
        }
        catch (const std::exception& e)
        {
            LogPrintf("%s: %s on strOutputIndex\n", __func__, e.what());
            return false;
        }

        bool found = false;
        for (COutput& out : possibleCoins) {
            if (UintToArith256(out.tx->GetHash()) == txHash && out.i == outputIndex) {
                selectedOutput = &out;
                found = true;
                break;
            }
        }
        if (!found) {
            LogPrintf("CActiveMasternode::GetMasterNodeVin - Could not locate valid vin\n");
            return false;
        }
    } else {
        // No output specified,  Select the first one
        if (possibleCoins.size() > 0) {
            selectedOutput = &possibleCoins[0];
        } else {
            LogPrintf("CActiveMasternode::GetMasterNodeVin - Could not locate specified vin from possible list\n");
            return false;
        }
    }
    // At this point we have a selected output, retrieve the associated info
    return GetVinFromOutput(*selectedOutput, vin, pubkey, secretKey);
}

bool CActiveMasternode::GetMasterNodeVinForPubKey(std::string collateralAddress, CTxIn& vin, CPubKey& pubkey, CKey& secretKey) {
    return GetMasterNodeVinForPubKey(collateralAddress, vin, pubkey, secretKey, "", "");
}

bool CActiveMasternode::GetMasterNodeVinForPubKey(std::string collateralAddress, CTxIn& vin, CPubKey& pubkey, CKey& secretKey, std::string strTxHash, std::string strOutputIndex) {
    CScript pubScript;

    // Find possible candidates
    vector<COutput> possibleCoins = SelectCoinsMasternodeForPubKey(collateralAddress);
    COutput* selectedOutput;

    // Find the vin
    if (!strTxHash.empty()) {
        // Let's find it
        arith_uint256 txHash(strTxHash);
        int outputIndex = boost::lexical_cast<int>(strOutputIndex);
        bool found = false;
        for (COutput& out : possibleCoins) {
            if (UintToArith256(out.tx->GetHash()) == txHash && out.i == outputIndex) {
                selectedOutput = &out;
                found = true;
                break;
            }
        }
        if (!found) {
            LogPrintf("CActiveMasternode::GetMasterNodeVinForPubKey - Could not locate valid vin\n");
            return false;
        }
    } else {
        // No output specified,  Select the first one
        if (possibleCoins.size() > 0) {
            selectedOutput = &possibleCoins[0];
        } else {
            LogPrintf("CActiveMasternode::GetMasterNodeVinForPubKey - Could not locate specified vin from possible list\n");
            return false;
        }
    }

    // At this point we have a selected output, retrieve the associated info
    return GetVinFromOutput(*selectedOutput, vin, pubkey, secretKey);
}

// Extract masternode vin information from output
bool CActiveMasternode::GetVinFromOutput(COutput out, CTxIn& vin, CPubKey& pubkey, CKey& secretKey) {

    CScript pubScript;

    vin = CTxIn(out.tx->GetHash(), out.i);
    pubScript = out.tx->tx->vout[out.i].scriptPubKey; // the inputs PubKey

    CTxDestination address1;
    ExtractDestination(pubScript, address1);

    const CKeyID* keyID = boost::get<CKeyID>(&address1);
    if (!keyID) {
        LogPrintf("CActiveMasternode::GetMasterNodeVin - Address does not refer to a key\n");
        return false;
    }


    std::string wallet_name = "";
    std::shared_ptr<CWallet> pwallet = GetWallet(wallet_name);
    if (!pwallet->GetKey(*keyID, secretKey)) {
        LogPrintf ("CActiveMasternode::GetMasterNodeVin - Private key for address is not known\n");
        return false;
    }

    pubkey = secretKey.GetPubKey();
    return true;
}

// get all possible outputs for running masternode
vector<COutput> CActiveMasternode::SelectCoinsMasternode() {
    vector<COutput> vCoins;
    vector<COutput> filteredCoins;

    // Retrieve all possible outputs
    std::string wallet_name = "";
    std::shared_ptr<CWallet> pwallet = GetWallet(wallet_name);
    pwallet->AvailableCoinsMN(vCoins);

    // Filter
    for (const COutput& out : vCoins) {
        int mncolletral = chainActive.Height() >=30000 ? 10000 : 10000;
        if (out.tx->tx->vout[out.i].nValue == mncolletral * COIN) {  //exactly DARKSEND_COLLATERAL XLT
            filteredCoins.push_back(out);
        }
    }
    return filteredCoins;
}

// get all possible outputs for running masternode for a specific pubkey
vector <COutput> CActiveMasternode::SelectCoinsMasternodeForPubKey(std::string collateralAddress) {
    static const int64_t DARKSEND_COLLATERAL = GetMNCollateral(chainActive.Height()) * COIN; //(10000*COIN); //10000 XLT
    CTxDestination address = DecodeDestination(collateralAddress);
    CScript scriptPubKey = GetScriptForDestination(address);
    vector <COutput> vCoins;
    vector <COutput> filteredCoins;

    // Retrieve all possible outputs
    std::string wallet_name = "";
    std::shared_ptr<CWallet> pwallet = GetWallet(wallet_name);
    pwallet->AvailableCoinsMN(vCoins);

    // Filter
    for (const COutput& out : vCoins) {
        if (out.tx->tx->vout[out.i].scriptPubKey == scriptPubKey && out.tx->tx->vout[out.i].nValue == DARKSEND_COLLATERAL) { //exactly 161.200 XLT
            filteredCoins.push_back(out);
        }
    }
    return filteredCoins;
}

// when starting a masternode, this can enable to run as a hot wallet with no funds
bool CActiveMasternode::EnableHotColdMasterNode(CTxIn& newVin, CService& newService) {
    if (!fMasterNode) return false;

    status = MASTERNODE_REMOTELY_ENABLED;

    //The values below are needed for signing dseep messages going forward
    this->vin = newVin;
    this->service = newService;

    LogPrintf("CActiveMasternode::EnableHotColdMasterNode() - Enabled! You may shut down the cold daemon.\n");

    return true;
}
