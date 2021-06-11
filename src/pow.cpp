// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>
#include "validation.h"
#include <chainparams.h>

// Nexalt modified: find last block index up to pindex
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake)
{
    CBlock block;
    if (IsBlockPruned(pindex)) {}
    if (!ReadBlockFromDiskPow(block, pindex, Params().GetConsensus())) {}

    int i = 0;
    while (pindex && pindex->pprev && (block.IsProofOfStake() != fProofOfStake) && i < 4000) {
        pindex = pindex->pprev;
        if (IsBlockPruned(pindex)) {}
        if (!ReadBlockFromDiskPow(block, pindex, Params().GetConsensus())) {}
        if (i == 3999){
            pindex = ::chainActive[1];
        }
        i++;
    }
    return pindex;
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params, bool fProofOfStake)
{
    const CBlockIndex* difficultyAdjustment = pindexLast;
    if ((pblock->GetBlockTime() >= START_POS_BLOCK) /*&& fProofOfStake*/) {
        if (!fProofOfStake) {
            pindexLast = GetLastBlockIndex(pindexLast, fProofOfStake);
            //assert(pindexLast != nullptr);

            unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();
            // Only change once per difficulty adjustment interval
            bool newRule;
            if (Params().NetworkIDString() == CBaseChainParams::TESTNET) {
                newRule = pblock->GetBlockTime() >= 1615204461;
            }
            else {
                newRule = pblock->GetBlockTime() >= NEW_DIFFICULTY_RULE;
            }
            if (newRule) {

                if ((difficultyAdjustment->nHeight + 1) % params.DifficultyAdjustmentInterval() != 0) {
                    if (params.fPowAllowMinDifficultyBlocks) {
                        // Special difficulty rule for testnet:
                        // If the new block's timestamp is more than 2* 10 minutes
                        // then allow mining of a min-difficulty block.
                        if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 2)
                            return nProofOfWorkLimit;
                        else {
                            // Return the last non-special-min-difficulty-rules-block
                            const CBlockIndex *pindex = pindexLast;
                            while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 &&
                                   pindex->nBits == nProofOfWorkLimit)
                                pindex = pindex->pprev;
                            return pindex->nBits;
                        }
                    }
                    return pindexLast->nBits;
                }
            }else{
            if ((pindexLast->nHeight + 1) % params.DifficultyAdjustmentInterval() != 0) {
                if (params.fPowAllowMinDifficultyBlocks) {
                    // Special difficulty rule for testnet:
                    // If the new block's timestamp is more than 2* 10 minutes
                    // then allow mining of a min-difficulty block.
                    if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 2) {
                        return nProofOfWorkLimit;
                    }
                    else {
                        // Return the last non-special-min-difficulty-rules-block
                        const CBlockIndex *pindex = pindexLast;
                        while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 &&
                               pindex->nBits == nProofOfWorkLimit)
                            pindex = pindex->pprev;
                        return pindex->nBits;
                    }
                }
                return pindexLast->nBits;
            }
        }

            // Go back by what we want to be 14 days worth of blocks
            // Nexalt: This fixes an issue where a 51% attack can change difficulty at will.
            // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
            int blockstogoback = params.DifficultyAdjustmentInterval() - 1;
            if ((pindexLast->nHeight + 1) != params.DifficultyAdjustmentInterval())
                blockstogoback = params.DifficultyAdjustmentInterval();

            // Go back by what we want to be 14 days worth of blocks
            const CBlockIndex *pindexFirst = pindexLast;
            for (int i = 0; pindexFirst && i < blockstogoback; i++)
                pindexFirst = pindexFirst->pprev;

            assert(pindexFirst);

            return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
        }
        else {
        int64_t nTargetSpacing = params.nPowTargetSpacing;
        int64_t nTargetTimespan = params.nPowTargetTimespan;
        arith_uint256 bnTargetLimit = UintToArith256(params.powLimit).GetCompact();

        if(fProofOfStake) {
            bnTargetLimit = UintToArith256(GetProofOfStakeLimit(pindexLast->nHeight));
        }


        if (pindexLast == nullptr) // Nexalt Modified
            return bnTargetLimit.GetCompact();

        const CBlockIndex *pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);
            
            if(pindexPrev == nullptr){
                return bnTargetLimit.GetCompact(); // first block
            }
        if (pindexPrev->pprev == nullptr) {
            return bnTargetLimit.GetCompact(); // first block
        }

        const CBlockIndex *pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);
        if (pindexPrevPrev->pprev == nullptr) {
            return bnTargetLimit.GetCompact(); // second block
        }

        int64_t nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();
        if (nActualSpacing < 0) {
            nActualSpacing = nTargetSpacing;
        }

        // ppcoin: target change every block
        // ppcoin: retarget with exponential moving toward target spacing
        arith_uint256 bnNew;
        bnNew.SetCompact(pindexPrev->nBits); // Replaced pindexLast to avoid bugs

        int64_t nInterval = nTargetTimespan / nTargetSpacing;
        bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
        bnNew /= ((nInterval + 1) * nTargetSpacing);

        if (bnNew <= 0 || bnNew > bnTargetLimit) {
            bnNew = bnTargetLimit;
        }
        return bnNew.GetCompact();
    }
    }else {
        if (pindexLast == nullptr){
            pindexLast = chainActive.Tip();
        }
        //assert(pindexLast != nullptr);

        unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();
        // Only change once per difficulty adjustment interval
        if ((pindexLast->nHeight + 1) % params.DifficultyAdjustmentInterval() != 0) {
            if (params.fPowAllowMinDifficultyBlocks) {
                // Special difficulty rule for testnet:
                // If the new block's timestamp is more than 2* 10 minutes
                // then allow mining of a min-difficulty block.
                if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 2)
                    return nProofOfWorkLimit;
                else {
                    // Return the last non-special-min-difficulty-rules-block
                    const CBlockIndex *pindex = pindexLast;
                    while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 &&
                           pindex->nBits == nProofOfWorkLimit)
                        pindex = pindex->pprev;
                    return pindex->nBits;
                }
            }
            return pindexLast->nBits;
        }

        // Go back by what we want to be 14 days worth of blocks
        // Nexalt: This fixes an issue where a 51% attack can change difficulty at will.
        // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
        int blockstogoback = params.DifficultyAdjustmentInterval() - 1;
        if ((pindexLast->nHeight + 1) != params.DifficultyAdjustmentInterval())
            blockstogoback = params.DifficultyAdjustmentInterval();

        // Go back by what we want to be 14 days worth of blocks
        const CBlockIndex *pindexFirst = pindexLast;
        for (int i = 0; pindexFirst && i < blockstogoback; i++)
            pindexFirst = pindexFirst->pprev;

        assert(pindexFirst);

        return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
    }
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;


        // Limit adjustment step
        int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
        if (nActualTimespan < params.nPowTargetTimespan / 4)
            nActualTimespan = params.nPowTargetTimespan / 4;
        if (nActualTimespan > params.nPowTargetTimespan * 4)
            nActualTimespan = params.nPowTargetTimespan * 4;

        // Retarget
        arith_uint256 bnNew;
        arith_uint256 bnOld;
        bnNew.SetCompact(pindexLast->nBits);
        bnOld = bnNew;
        // Nexalt: intermediate uint256 can overflow by 1 bit
        const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
        bool fShift = bnNew.bits() > bnPowLimit.bits() - 1;
        if (fShift)
            bnNew >>= 1;
        bnNew *= nActualTimespan;
        bnNew /= params.nPowTargetTimespan;
        if (fShift)
            bnNew <<= 1;

        if (bnNew > bnPowLimit)
            bnNew = bnPowLimit;

        return bnNew.GetCompact();

}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
