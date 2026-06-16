package bip

import (
	"encoding/binary"

	"github.com/Nux-xader/sela/sela-vault/util"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

// AccountDerivation holds the account-level derivation details.
type AccountDerivation struct {
	MasterFP      uint32
	ParentFPBytes []byte
	AccountKey    *hdkeychain.ExtendedKey
}

// DeriveAccountDerivation derives the BIP-84 account key m/84'/(0'|1')/accountIdx' from seed.
// The caller is responsible for calling AccountKey.Zero() when finished.
func DeriveAccountDerivation(seed []byte, isTestnet bool, accountIdx uint32) (*AccountDerivation, error) {
	var netParams *chaincfg.Params
	if isTestnet {
		netParams = &chaincfg.TestNet3Params
	} else {
		netParams = &chaincfg.MainNetParams
	}

	master, err := hdkeychain.NewMaster(seed, netParams)
	if err != nil {
		return nil, err
	}
	defer master.Zero()

	// Calculate master fingerprint (first 4 bytes of Hash160 of master public key)
	masterPub, err := master.ECPubKey()
	if err != nil {
		return nil, err
	}
	masterFPBytes := btcutil.Hash160(masterPub.SerializeCompressed())[:4]
	masterFP := binary.BigEndian.Uint32(masterFPBytes)

	// Derive Path: m/84'/(0'|1')/accountIdx'
	purpose := uint32(84 + hdkeychain.HardenedKeyStart)
	coinType := uint32(0 + hdkeychain.HardenedKeyStart)
	if isTestnet {
		coinType = uint32(1 + hdkeychain.HardenedKeyStart)
	}
	account := uint32(accountIdx + hdkeychain.HardenedKeyStart)

	m84, err := master.Derive(purpose)
	if err != nil {
		return nil, err
	}
	defer m84.Zero()

	m84Coin, err := m84.Derive(coinType)
	if err != nil {
		return nil, err
	}
	defer m84Coin.Zero()

	m84Acc, err := m84Coin.Derive(account)
	if err != nil {
		return nil, err
	}

	parentFPBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(parentFPBytes, m84Acc.ParentFingerprint())

	return &AccountDerivation{
		MasterFP:      masterFP,
		ParentFPBytes: parentFPBytes,
		AccountKey:    m84Acc,
	}, nil
}

// DeriveBIP84Address derives the Native Segwit Bitcoin Address (Bech32) at the default receiving index
// using the derivation path: m/84'/(0'|1')/accountIdx'/0/0
func DeriveBIP84Address(mnemonicBytes []byte, passphraseBytes []byte, isTestnet bool, accountIdx uint32) (string, error) {
	// Generate Seed (64 bytes)
	seed := MnemonicToSeed(mnemonicBytes, passphraseBytes)
	defer util.WipeBytes(seed)

	// Derive account key
	deriv, err := DeriveAccountDerivation(seed, isTestnet, accountIdx)
	if err != nil {
		return "", err
	}
	defer deriv.AccountKey.Zero()

	// Derive: accountKey/0/0
	change := uint32(0)
	m84Change, err := deriv.AccountKey.Derive(change)
	if err != nil {
		return "", err
	}
	defer m84Change.Zero()

	index := uint32(0)
	leaf, err := m84Change.Derive(index)
	if err != nil {
		return "", err
	}
	defer leaf.Zero()

	// Get Public Key from leaf
	pubKey, err := leaf.ECPubKey()
	if err != nil {
		return "", err
	}

	// Generate BIP-84 Address (Bech32 P2WPKH: bc1q... or tb1q...)
	var netParams *chaincfg.Params
	if isTestnet {
		netParams = &chaincfg.TestNet3Params
	} else {
		netParams = &chaincfg.MainNetParams
	}

	witnessProgram := btcutil.Hash160(pubKey.SerializeCompressed())
	witnessAddr, err := btcutil.NewAddressWitnessPubKeyHash(witnessProgram, netParams)
	if err != nil {
		return "", err
	}

	return witnessAddr.EncodeAddress(), nil
}
