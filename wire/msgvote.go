package wire

import (
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"golang.org/x/crypto/ripemd160"
)

type VoteType uint8

const (
	VTCertify VoteType = iota
	VTUniqueAnnounce
)

type MsgVote struct {
	Address        string
	VotedBlockHash chainhash.Hash
	Type           VoteType
}

// TODO: see https://github.com/SebastianElvis/orazor/issues/8

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgVote) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	return writeElements(w, msg.Address, &msg.VotedBlockHash, msg.Type)
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
func (msg *MsgVote) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	return readElements(r, msg.Address, &msg.VotedBlockHash, msg.Type)
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgVote) Command() string {
	return CmdVote
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgVote) MaxPayloadLength(pver uint32) uint32 {
	return 1 + ripemd160.Size + chainhash.HashSize + 1
}

// MsgVote returns a new message that conforms to the Message
// interface.  See MsgVote for details.
func NewMsgVote() *MsgVote {
	return &MsgVote{}
}
