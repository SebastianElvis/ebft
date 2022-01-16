package wire

import (
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

type VoteType uint8

const (
	VTCertify VoteType = iota
	VTUniqueAnnounce
)

// MsgVote mplements the Message interface and represents a vote message.
// It is used for a peer to advertise its vote on a block. Note that the
// signature in is a compact signature that includes signer's PK.
// See `SignCompact` and `RecoverCompact`.
type MsgVote struct {
	VotedBlockHash chainhash.Hash
	Type           VoteType
	Signature      []byte // compact signature of H(VotedBlockHash + Type)
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgVote) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	return writeElements(w, &msg.VotedBlockHash, msg.Type, &msg.Signature)
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
func (msg *MsgVote) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	return readElements(r, &msg.VotedBlockHash, msg.Type, &msg.Signature)
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgVote) Command() string {
	return CmdVote
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgVote) MaxPayloadLength(pver uint32) uint32 {
	// A message signature has a customized encoding and is at most 72 bytes
	// https://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long
	return 1 + chainhash.HashSize + 72 + 1
}

// MsgVote returns a new message that conforms to the Message
// interface.  See MsgVote for details.
func NewMsgVote() *MsgVote {
	return &MsgVote{}
}
