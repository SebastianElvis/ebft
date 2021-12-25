package blockchain

import (
	"github.com/btcsuite/btcd/txscript"
)

func (c *chainView) tail(n int32) []*blockNode {
	var lastBlocks []*blockNode
	cur_block := c.tip()
	for i := int32(0); i < n; i++ {
		lastBlocks = append(lastBlocks, cur_block)
		if cur_block.parent == nil {
			break
		} else {
			cur_block = cur_block.parent
		}
	}
	return lastBlocks
}

func (c *chainView) Tail(n int32) []*blockNode {
	c.mtx.Lock()
	lastBlocks := c.tail(n)
	c.mtx.Unlock()
	return lastBlocks
}

func (b *BlockChain) Committee(n int32) (map[string]int32, error) {
	committee := make(map[string]int32)
	lastBlocks := b.bestChain.Tail(n)
	for _, blockNode := range lastBlocks {
		// get the block hash
		blockHash := blockNode.hash
		// get the block from DB
		block, err := b.BlockByHash(&blockHash)
		if err != nil {
			return nil, err
		}
		// get the coinbase tx (which is always the first tx) in the block
		coinbaseTx, err := block.Tx(0)
		if err != nil {
			log.Debugf("Get coinbase tx: %v", err)
			return nil, err
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
			return nil, err
		}
		// the readable address can be extracted by `addr.EncodeAddress()`
		addr := addrs[0].EncodeAddress()

		// add weight of this addr
		if _, ok := committee[addr]; ok {
			committee[addr] += 1
		} else {
			committee[addr] = 1
		}
	}
	return committee, nil
}