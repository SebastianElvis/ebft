package wire

import "github.com/btcsuite/btcd/chaincfg/chainhash"

type MsgVote struct {
	Address        string
	VotedBlockHash chainhash.Hash
}

// TODO: see https://github.com/SebastianElvis/orazor/issues/3
