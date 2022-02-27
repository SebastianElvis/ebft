package blockchain

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

func (b *BlockChain) ProcessVote(vote *wire.MsgVote) error {
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

	if b.chainParams.Extension == chaincfg.ExtSyncORazor {
		// SyncORazor does not have UniqueAnnounce
		if voteType == wire.VTUniqueAnnounce {
			return fmt.Errorf("wrong vote type in SyncORazor-simnet: VTUniqueAnnounce")
		}
		// get the block
		block, err := b.BlockByHash(&votedBlockHash)
		if err != nil {
			return fmt.Errorf("block %v does not exist: %v", votedBlockHash, err)
		}
		// get the blockNode
		blockNode := b.index.LookupNode(&votedBlockHash)
		// if the block is already certified or finalised, return nil directly
		if blockNode.status.KnownCertified() {
			return fmt.Errorf("block %v is already certified or finalised", votedBlockHash)
		}
		// add vote
		if _, ok := blockNode.certifyVotes[addr]; !ok {
			blockNode.certifyVotes[addr] = vote
		}
		// if meet the certify requirement, certify the block
		quorum := b.chainParams.CommitteeSize*2/3 + 1
		var totalVotes uint32 = 0
		committee, err := b.Committee(b.chainParams.CommitteeSize)
		if err != nil {
			return err
		}
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
				return err
			}

			// refresh the committee
			b.committeeAddrs, err = b.Committee(b.chainParams.CommitteeSize)
			if err != nil {
				return fmt.Errorf("refresh committee upon new block %v", votedBlockHash)
			}
			// if 3Delta has not yet passed, finalise the block and all its ancestors
			if !blockNode.timerFired {
				blockNode.status = statusFinalized
				curBlock := blockNode.parent
				for {
					if !curBlock.status.KnownFinalized() {
						curBlock.status = statusFinalized
						curBlock = curBlock.parent
					} else {
						break
					}
				}
			}
		}
	} else if b.chainParams.Extension == chaincfg.ExtPSyncORazor {
		// quorum size
		quorum := b.chainParams.CommitteeSize*2/3 + 1
		// get the block
		block, err := b.BlockByHash(&votedBlockHash)
		if err != nil {
			return fmt.Errorf("block %v does not exist: %v", votedBlockHash, err)
		}
		// get the blockNode
		blockNode := b.index.LookupNode(&votedBlockHash)

		if voteType == wire.VTCertify {
			// if the block is already certified or finalised, return nil directly
			if blockNode.status.KnownCertified() {
				return fmt.Errorf("block %v is already certified or finalised", votedBlockHash)
			}

			// add vote
			if _, ok := blockNode.certifyVotes[addr]; !ok {
				blockNode.certifyVotes[addr] = vote
			}

			// if meet the certify requirement, certify the block
			var totalVotes uint32 = 0
			committee, err := b.Committee(b.chainParams.CommitteeSize)
			if err != nil {
				return err
			}
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
					return err
				}
			}
		} else if voteType == wire.VTUniqueAnnounce {
			// add vote
			if _, ok := blockNode.uniqueAnnounceVotes[addr]; !ok {
				blockNode.uniqueAnnounceVotes[addr] = vote
			}
			// if meet the finalisation requirement, finalise all blocks before this block
			var totalVotes uint32 = 0
			committee, err := b.Committee(b.chainParams.CommitteeSize)
			if err != nil {
				return err
			}
			for k := range blockNode.uniqueAnnounceVotes {
				if v, ok := committee[k]; ok {
					totalVotes += v
				}
			}
			if totalVotes >= quorum && blockNode.status.KnownCertified() {
				// finalise all previous blocks
				curBlock := blockNode
				for {
					parent := curBlock.parent
					if !parent.status.KnownFinalized() {
						parent.status = statusFinalized
						curBlock = parent
					} else {
						break
					}
				}
			}
		}

	} else {
		return fmt.Errorf("wrong network: %s", b.chainParams.Name)
	}
	return nil
}
