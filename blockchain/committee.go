package blockchain

import (
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
)

func (c *chainView) tail(n uint32) []*blockNode {
	var lastBlocks []*blockNode
	cur_block := c.tip()
	for i := uint32(0); i < n; i++ {
		lastBlocks = append(lastBlocks, cur_block)
		if cur_block.parent == nil {
			break
		} else {
			cur_block = cur_block.parent
		}
	}
	return lastBlocks
}

func (c *chainView) Tail(n uint32) []*blockNode {
	c.mtx.Lock()
	lastBlocks := c.tail(n)
	c.mtx.Unlock()
	return lastBlocks
}

func (b *BlockChain) Committee() (map[string]uint32, error) {
	// static committee policy
	committee := make(map[string]uint32)

	for i := uint32(0); i < b.chainParams.CommitteeSize; i++ {
		addr := addressList[i]
		committee[addr] = 1
	}
	return committee, nil
}

func (b *BlockChain) CommitteeLastN() (map[string]uint32, error) {
	committee := make(map[string]uint32)
	lastBlocks := b.bestChain.Tail(b.chainParams.CommitteeSize)
	for _, blockNode := range lastBlocks {
		// get the block hash
		blockHash := blockNode.hash
		// get the block from DB
		block, err := b.BlockByHash(&blockHash)
		if err != nil {
			return nil, err
		}
		// the readable address can be extracted by `addr.EncodeAddress()`
		minerAddr, err := b.GetMiner(block)
		if err != nil {
			return nil, err
		}
		// add weight of this addr
		committee[minerAddr] += 1
	}
	return committee, nil
}

func (b *BlockChain) GetMiner(block *btcutil.Block) (string, error) {
	// get the coinbase tx (which is always the first tx) in the block
	coinbaseTx, err := block.Tx(0)
	if err != nil {
		log.Debugf("Get coinbase tx: %v", err)
		return "", err
	}
	// get the coinbase tx's output
	// the coinbase tx  always contains a single output
	txOut := coinbaseTx.MsgTx().TxOut[0]
	// get the PkScript in the txout
	pkScriptBytes := txOut.PkScript
	// extract scriptClass and address from pkScriptBytes
	// we don't consider coinbase txs with multiple miners (e.g., P2Pool)
	scriptClass, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScriptBytes, b.chainParams)
	if err != nil {
		log.Debugf("PkScript class: %v; addrs: %v, err: %v", scriptClass, addrs, err)
		return "", err
	}
	// the readable address can be extracted by `addr.EncodeAddress()`
	return addrs[0].EncodeAddress(), nil
}
