package blockchain

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

// ProcessVote processes a vote message
// returns (newlyCertified, duplicatedVote, error)
func (b *BlockChain) ProcessVote(vote *wire.MsgVote) (bool, bool, error) {
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

	// get the committee
	committee, err := b.Committee()
	if err != nil {
		return false, false, err
	}
	// the voter should be a part of the committee
	addr := string(vote.Address[:])
	if _, ok := committee[addr]; !ok {
		return false, false, fmt.Errorf("voter %v is not a part of the committee", addr)
	}

	if b.chainParams.Extension == chaincfg.ExtSyncORazor {
		return b.syncProcessVote(vote)
	} else if b.chainParams.Extension == chaincfg.ExtPSyncORazor {
		return b.psyncProcessVote(vote)
	} else {
		return false, false, fmt.Errorf("vote message cam only exist with extension ExtSyncORazor or ExtPSyncORazor")
	}
}

// ProcessVote processes a vote message
// returns (newlyCertified, duplicatedVote, error)
func (b *BlockChain) syncProcessVote(vote *wire.MsgVote) (bool, bool, error) {
	votedBlockHash := vote.VotedBlockHash
	voteType := vote.Type
	addr := string(vote.Address[:])

	// SyncORazor does not have UniqueAnnounce
	if voteType != wire.VTCertify {
		return false, false, fmt.Errorf("wrong vote type in SyncORazor-simnet: %s", voteType.String())
	}

	// quorum
	quorum := b.chainParams.CommitteeSize*1/2 + 1
	committee, err := b.Committee()
	if err != nil {
		return false, false, err
	}
	// the voter should be a part of the committee
	if _, ok := committee[addr]; !ok {
		return false, false, fmt.Errorf("voter %v is not a part of the committee", addr)
	}

	// get the block
	block, err := b.BlockByHashNoMainChain(&votedBlockHash)
	if err != nil {
		return false, false, fmt.Errorf("voted block %v does not exist: %v", votedBlockHash, err)
	}
	// get the blockNode
	blockNode := b.index.LookupNode(&votedBlockHash)
	// if the block is already certified or finalised, return (false, false, nil)
	if blockNode.status.KnownCertified() {
		return false, false, nil
	}

	// add vote
	if _, ok := blockNode.certifyVotes[addr]; !ok {
		blockNode.certifyVotes[addr] = vote
	} else {
		// duplicated vote, skip
		return false, true, nil
	}

	// if **newly** meet the certify requirement,
	//   - certify the block
	//   - refresh the best chain
	//   - refresh the committee
	if totalCertifyVotes(blockNode, committee) == quorum {
		// certify the block
		b.index.SetStatusFlags(blockNode, statusCertified)
		// change the bestchain
		b.chainLock.Lock()
		if _, err := b.connectBestChain(blockNode, block, BFNone); err != nil {
			return false, false, err
		}
		b.chainLock.Unlock()
		log.Infof("extension SyncORazor: block %v has been certified", blockNode.hash)
		// refresh the committee
		b.committeeAddrs, err = b.Committee()
		if err != nil {
			return false, false, fmt.Errorf("refresh committee upon new block %v", votedBlockHash)
		}
		return true, false, nil
	} else {
		return false, false, nil
	}
}

// ProcessVote processes a vote message
// returns (newlyCertified, duplicatedVote, error)
func (b *BlockChain) psyncProcessVote(vote *wire.MsgVote) (bool, bool, error) {
	votedBlockHash := vote.VotedBlockHash
	voteType := vote.Type
	addr := string(vote.Address[:])

	// quorum size
	quorum := b.chainParams.CommitteeSize*2/3 + 1
	// get the committee
	committee, err := b.Committee()
	if err != nil {
		return false, false, err
	}
	// the voter should be a part of the committee
	if _, ok := committee[addr]; !ok {
		return false, false, fmt.Errorf("voter %v is not a part of the committee", addr)
	}

	// get the block
	block, err := b.BlockByHashNoMainChain(&votedBlockHash)
	if err != nil {
		return false, false, fmt.Errorf("block %v does not exist: %v", votedBlockHash, err)
	}
	// get the blockNode
	blockNode := b.index.LookupNode(&votedBlockHash)

	// this is a certify vote
	if voteType == wire.VTCertify {
		// if the block is already certified or finalised, return (false, false, nil)
		if blockNode.status.KnownCertified() {
			return false, false, nil
		}
		// add vote
		if _, ok := blockNode.certifyVotes[addr]; !ok {
			blockNode.certifyVotes[addr] = vote
		} else {
			// duplicated vote, skip
			return false, true, nil
		}
		// if **newly** meet the certify requirement
		//   - certify the block
		//   - refresh the best chain
		//   - refresh the committee
		if totalCertifyVotes(blockNode, committee) == quorum {
			// certify the block
			b.index.SetStatusFlags(blockNode, statusCertified)
			// change the bestchain
			b.chainLock.Lock()
			if _, err := b.connectBestChain(blockNode, block, BFNone); err != nil {
				return false, false, err
			}
			b.chainLock.Unlock()
			log.Infof("extension PSyncORazor: block %v has been certified", blockNode.hash)
			return true, false, nil
		} else {
			return false, false, nil
		}
	}

	// this is a unique announce vote
	if voteType == wire.VTUniqueAnnounce {
		// the voted block should be certified
		if !blockNode.status.KnownCertified() {
			return false, false, fmt.Errorf("the UA-voted block %v is not certified yet", blockNode.hash)
		}

		// add vote
		if _, ok := blockNode.uniqueAnnounceVotes[addr]; !ok {
			blockNode.uniqueAnnounceVotes[addr] = vote
		} else {
			// duplicated vote
			return false, true, nil
		}
		// if **newly** meet the finalisation requirement
		//   - finalise the block and its ancestors
		if totalUAVotes(blockNode, committee) == quorum {
			curBlock := blockNode
			for {
				if !curBlock.status.KnownFinalized() {
					b.index.SetStatusFlags(blockNode, statusFinalized)
					log.Infof("extension PSyncORazor: block %v has been finalised", curBlock.hash)
					if curBlock.parent == nil {
						break
					} else {
						curBlock = curBlock.parent
					}
				} else {
					break
				}
			}
			return true, false, nil
		}
	}
	return false, false, fmt.Errorf("unknown vote type: %s", voteType.String())
}

func totalCertifyVotes(node *blockNode, committee map[string]uint32) uint32 {
	// if meet the certify requirement, certify the block
	var totalVotes uint32 = 0
	for k := range node.certifyVotes {
		if v, ok := committee[k]; ok {
			totalVotes += v
		}
	}
	return totalVotes
}

func totalUAVotes(node *blockNode, committee map[string]uint32) uint32 {
	// if meet the certify requirement, certify the block
	var totalVotes uint32 = 0
	for k := range node.uniqueAnnounceVotes {
		if v, ok := committee[k]; ok {
			totalVotes += v
		}
	}
	return totalVotes
}
