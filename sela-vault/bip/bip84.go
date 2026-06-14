package bip

import (
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

// DeriveBIP84Address derives the Native Segwit Bitcoin Address (Bech32) at a specific receiving index
// using the derivation path: m/84'/0'/0'/0/index
func DeriveBIP84Address(mnemonicBytes []byte, passphraseBytes []byte, index uint32) (string, error) {
	// 1. Generate Seed (64 bytes)
	seed := MnemonicToSeed(mnemonicBytes, passphraseBytes)
	defer WipeBytes(seed)

	// 2. Select Network Params
	netParams := &chaincfg.MainNetParams

	// 3. Generate Master Key (BIP-32 Root)
	master, err := hdkeychain.NewMaster(seed, netParams)
	if err != nil {
		return "", err
	}
	defer master.Zero()

	// 4. Derive Path: m/84'/0'/0'/0/index
	purpose := uint32(84 + hdkeychain.HardenedKeyStart)
	coinType := uint32(0 + hdkeychain.HardenedKeyStart)
	account := uint32(0 + hdkeychain.HardenedKeyStart)
	change := uint32(0)

	// m/84'
	m84, err := master.Derive(purpose)
	if err != nil {
		return "", err
	}
	defer m84.Zero()

	// m/84'/0'
	m84Coin, err := m84.Derive(coinType)
	if err != nil {
		return "", err
	}
	defer m84Coin.Zero()

	// m/84'/0'/0'
	m84Acc, err := m84Coin.Derive(account)
	if err != nil {
		return "", err
	}
	defer m84Acc.Zero()

	// m/84'/0'/0'/0
	m84Change, err := m84Acc.Derive(change)
	if err != nil {
		return "", err
	}
	defer m84Change.Zero()

	// m/84'/0'/0'/0/index
	leaf, err := m84Change.Derive(index)
	if err != nil {
		return "", err
	}
	defer leaf.Zero()

	// 5. Get Public Key from leaf
	pubKey, err := leaf.ECPubKey()
	if err != nil {
		return "", err
	}

	// 6. Generate BIP-84 Address (Bech32 P2WPKH: bc1q...)
	witnessProgram := btcutil.Hash160(pubKey.SerializeCompressed())
	witnessAddr, err := btcutil.NewAddressWitnessPubKeyHash(witnessProgram, netParams)
	if err != nil {
		return "", err
	}

	return witnessAddr.EncodeAddress(), nil
}
