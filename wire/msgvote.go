package wire

import (
	"fmt"
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

type VoteType uint32

const (
	VTCertify VoteType = iota
	VTUniqueAnnounce
)

func (t VoteType) String() string {
	return [...]string{"Certify", "UniqueAnnounce"}[t]
}

// MsgVote mplements the Message interface and represents a vote message.
// It is used for a peer to advertise its vote on a block.
// TODO (RH, non-urgent): SignCompact(sk, H(VotedBlockHash || Type)) rather than unsigned Address
type MsgVote struct {
	VotedBlockHash chainhash.Hash
	Type           VoteType
	Address        string
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgVote) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	if len(msg.Address) != 34 {
		return fmt.Errorf("len(addr) should be 34, while this one is %d", len(msg.Address))
	}
	var addrBytes [34]byte
	copy(addrBytes[:], msg.Address)
	return writeElements(w, &msg.VotedBlockHash, msg.Type, addrBytes)
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
func (msg *MsgVote) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	var addrBytes [34]byte
	if err := readElements(r, &msg.VotedBlockHash, &msg.Type, &addrBytes); err != nil {
		return err
	}
	msg.Address = string(addrBytes[:])
	if len(msg.Address) != 34 {
		return fmt.Errorf("len(addr) should be 34, while this one is %d", len(msg.Address))
	}
	return nil
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
	// return 1 + chainhash.HashSize + 72 + 1
	return 1 + chainhash.HashSize + 34 + 4
}

// MsgVote returns a new message that conforms to the Message
// interface.  See MsgVote for details.
func NewMsgVote() *MsgVote {
	return &MsgVote{}
}
