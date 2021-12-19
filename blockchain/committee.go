package blockchain

import (
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
)

func (c *chainView) tail(n int32) []*blockNode {
	var lastBlocks []*blockNode
	cur_block := c.tip()
	for i := int32(1); i < n; i++ {
		lastBlocks = append(lastBlocks, cur_block)
		cur_block = cur_block.parent
	}
	return lastBlocks
}

func (c *chainView) Tail(n int32) []*blockNode {
	c.mtx.Lock()
	lastBlocks := c.tail(n)
	c.mtx.Unlock()
	return lastBlocks
}

func (b *BlockChain) Committee(n int32) ([]btcutil.Address, error) {
	var committee []btcutil.Address
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
			return nil, err
		}
		// get the pkscript in the coinbase tx's output
		// in our case the coinbase tx always contains a single output
		pkScriptBytes := coinbaseTx.MsgTx().TxOut[0].PkScript
		// decode the pkscript bytes to pkscript
		pkScript, err := txscript.ParsePkScript(pkScriptBytes)
		if err != nil {
			return nil, err
		}
		// convert the pkscript to the address
		addr, err := pkScript.Address(b.chainParams)
		if err != nil {
			return nil, err
		}
		// append addr
		committee = append(committee, addr)
		// TODO test
	}
	return committee, nil
}
