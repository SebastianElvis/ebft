package blockchain

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

func (b *BlockChain) ProcessVote(vote *wire.MsgVote) (bool, error) {
	votedBlockHash := vote.VotedBlockHash
	voteType := vote.Type
	addr := vote.Address

	// signature := vote.Signature
	// // verify signature
	// pk, _, err := btcec.RecoverCompact(btcec.S256(), signature, votedBlockHash[:])
	// if err != nil {
	// 	log.Warnf("Failed to verify vote message %v: %v", vote, err)
	// }
	// // Create a new btcutil.Address from the public key
	// // Here the network does not matter
	// addr, err := btcutil.NewAddressPubKey(pk.SerializeCompressed(), &chaincfg.MainNetParams)
	// if err != nil {
	// 	return err
	// }

	committee, err := b.Committee(b.chainParams.CommitteeSize)
	if err != nil {
		return false, err
	}
	// the voter should be a part of the committee
	if _, ok := committee[addr]; !ok {
		return false, fmt.Errorf("voter %v is not a part of the committee", addr)
	}

	if b.chainParams.Extension == chaincfg.ExtSyncORazor {
		// quorum
		quorum := b.chainParams.CommitteeSize*1/2 + 1
		// SyncORazor does not have UniqueAnnounce
		if voteType == wire.VTUniqueAnnounce {
			return false, fmt.Errorf("wrong vote type in SyncORazor-simnet: VTUniqueAnnounce")
		}
		// get the block
		block, err := b.BlockByHash(&votedBlockHash)
		if err != nil {
			return false, fmt.Errorf("block %v does not exist: %v", votedBlockHash, err)
		}
		// get the blockNode
		blockNode := b.index.LookupNode(&votedBlockHash)
		// if the block is already certified or finalised, return nil directly
		if blockNode.status.KnownCertified() {
			return false, fmt.Errorf("block %v is already certified or finalised", votedBlockHash)
		}
		// add vote
		if _, ok := blockNode.certifyVotes[addr]; !ok {
			blockNode.certifyVotes[addr] = vote
		} else {
			return false, fmt.Errorf("vote %v is received more than once", vote)
		}
		// if meet the certify requirement, certify the block
		var totalVotes uint32 = 0
		for k := range blockNode.certifyVotes {
			if v, ok := committee[k]; ok {
				totalVotes += v
			}
		}
		if totalVotes >= quorum {
			// certify the block
			blockNode.status = statusCertified
			// change the bestchain
			if _, err := b.connectBestChain(blockNode, block, BFNone); err != nil {
				return false, err
			}
			// refresh the committee
			b.committeeAddrs, err = b.Committee(b.chainParams.CommitteeSize)
			if err != nil {
				return false, fmt.Errorf("refresh committee upon new block %v", votedBlockHash)
			}
			return true, nil
		} else {
			return false, nil
		}
	} else if b.chainParams.Extension == chaincfg.ExtPSyncORazor {
		// quorum size
		quorum := b.chainParams.CommitteeSize*2/3 + 1
		// get the block
		block, err := b.BlockByHash(&votedBlockHash)
		if err != nil {
			return false, fmt.Errorf("block %v does not exist: %v", votedBlockHash, err)
		}
		// get the blockNode
		blockNode := b.index.LookupNode(&votedBlockHash)

		if voteType == wire.VTCertify {
			// if the block is already certified or finalised, return nil directly
			if blockNode.status.KnownCertified() {
				return false, fmt.Errorf("block %v is already certified or finalised", votedBlockHash)
			}
			// add vote
			if _, ok := blockNode.certifyVotes[addr]; !ok {
				blockNode.certifyVotes[addr] = vote
			} else {
				return false, fmt.Errorf("vote %v is received more than once", vote)
			}
			// if meet the certify requirement, certify the block
			var totalVotes uint32 = 0
			for k := range blockNode.certifyVotes {
				if v, ok := committee[k]; ok {
					totalVotes += v
				}
			}
			if totalVotes >= quorum {
				// certify the block
				blockNode.status = statusCertified
				// change the bestchain
				if _, err := b.connectBestChain(blockNode, block, BFNone); err != nil {
					return false, err
				}
				return true, nil
			} else {
				return false, nil
			}
		} else if voteType == wire.VTUniqueAnnounce {
			// add vote
			if _, ok := blockNode.uniqueAnnounceVotes[addr]; !ok {
				blockNode.uniqueAnnounceVotes[addr] = vote
			} else {
				return false, fmt.Errorf("vote %v is received more than once", vote)
			}
			// if meet the finalisation requirement, finalise all blocks before this block
			var totalVotes uint32 = 0
			for k := range blockNode.uniqueAnnounceVotes {
				if v, ok := committee[k]; ok {
					totalVotes += v
				}
			}
			if totalVotes >= quorum && blockNode.status.KnownCertified() {
				// finalise the block and its ancestors
				curBlock := blockNode
				for {
					if !curBlock.status.KnownFinalized() {
						curBlock.status = statusFinalized
						curBlock = curBlock.parent
					} else {
						break
					}
				}
				return true, nil
			}
		}
	} else {
		return false, fmt.Errorf("wrong network: %s", b.chainParams.Name)
	}
	return false, nil
}
