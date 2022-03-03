package chaincfg

import (
	"math"
	"time"

	"github.com/btcsuite/btcd/wire"
)

// Extension: Crystal, SyncORazor, PSyncORazor
type ExtensionType uint8

const (
	ExtNone ExtensionType = iota
	ExtCrystal
	ExtSyncORazor
	ExtPSyncORazor
)

func (t ExtensionType) String() string {
	return [...]string{"None", "Crystal", "SyncORazor", "PSyncORazor"}[t]
}

// TODO: function NewParamsWithExtension
func CustomExtSimNetParams(extension ExtensionType, committeeSize uint32, latency uint32) Params {
	return Params{
		Name:        "simnet",
		Net:         wire.SimNet,
		DefaultPort: "18555",
		DNSSeeds:    []DNSSeed{}, // NOTE: There must NOT be any seeds.

		// Chain parameters
		GenesisBlock:             &simNetGenesisBlock,
		GenesisHash:              &simNetGenesisHash,
		PowLimit:                 simNetPowLimit,
		PowLimitBits:             0x207fffff,
		BIP0034Height:            0, // Always active on simnet
		BIP0065Height:            0, // Always active on simnet
		BIP0066Height:            0, // Always active on simnet
		CoinbaseMaturity:         100,
		SubsidyReductionInterval: 210000,
		TargetTimespan:           time.Hour * 24 * 14, // 14 days
		TargetTimePerBlock:       time.Minute * 10,    // 10 minutes
		RetargetAdjustmentFactor: 4,                   // 25% less, 400% more
		ReduceMinDifficulty:      true,
		MinDiffReductionTime:     time.Minute * 20, // TargetTimePerBlock * 2
		GenerateSupported:        true,

		// Checkpoints ordered from oldest to newest.
		Checkpoints: nil,

		// Consensus rule change deployments.
		//
		// The miner confirmation window is defined as:
		//   target proof of work timespan / target proof of work spacing
		RuleChangeActivationThreshold: 75, // 75% of MinerConfirmationWindow
		MinerConfirmationWindow:       100,
		Deployments: [DefinedDeployments]ConsensusDeployment{
			DeploymentTestDummy: {
				BitNumber:  28,
				StartTime:  0,             // Always available for vote
				ExpireTime: math.MaxInt64, // Never expires
			},
			DeploymentCSV: {
				BitNumber:  0,
				StartTime:  0,             // Always available for vote
				ExpireTime: math.MaxInt64, // Never expires
			},
			DeploymentSegwit: {
				BitNumber:  1,
				StartTime:  0,             // Always available for vote
				ExpireTime: math.MaxInt64, // Never expires.
			},
		},

		// Mempool parameters
		RelayNonStdTxs: true,

		// Human-readable part for Bech32 encoded segwit addresses, as defined in
		// BIP 173.
		Bech32HRPSegwit: "sb", // always sb for sim net

		// Address encoding magics
		PubKeyHashAddrID:        0x3f, // starts with S
		ScriptHashAddrID:        0x7b, // starts with s
		PrivateKeyID:            0x64, // starts with 4 (uncompressed) or F (compressed)
		WitnessPubKeyHashAddrID: 0x19, // starts with Gg
		WitnessScriptHashAddrID: 0x28, // starts with ?

		// BIP32 hierarchical deterministic extended key magics
		HDPrivateKeyID: [4]byte{0x04, 0x20, 0xb9, 0x00}, // starts with sprv
		HDPublicKeyID:  [4]byte{0x04, 0x20, 0xbd, 0x3a}, // starts with spub

		// BIP44 coin type used in the hierarchical deterministic path for
		// address generation.
		HDCoinType: 115, // ASCII for s

		Extension:     extension,
		CommitteeSize: committeeSize,
		Latency:       latency,
	}
}
