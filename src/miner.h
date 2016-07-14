#ifndef MINER_H
#define MINER_H

#include "main.h"

using namespace std;
using namespace boost;


class CBlock;
class CReserveKey;
class CBlockIndex;
class CWallet;
class CBlockTemplate;

void GenerateBitcoins(bool fGenerate, CWallet* pwallet);

/** Check mined proof-of-stake block */
bool CheckStake(CBlock* pblock, CWallet& wallet);

/** Base sha256 mining transform */
void SHA256Transform(void* pstate, void* pinput, const void* pinit);

void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce);
void FormatHashBuffers(CBlock* pblock, char* pmidstate, char* pdata, char* phash1);
bool CheckWork(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey);

CBlock* CreateNewBlock(CWallet* pwallet, bool fProofOfStake=false);

/** Generate a new block, without valid proof-of-work */
CBlockTemplate* CreateNewBlock(const CScript& scriptPubKeyIn, bool fProofOfStake);
CBlockTemplate* CreateNewBlockWithKey(CReserveKey& reservekey, bool fProofOfStake);


#endif // MINER_H
