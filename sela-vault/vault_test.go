package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/Nux-xader/sela/sela-vault/bip"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func TestVaultEncryptDecryptArgon2id(t *testing.T) {
	mnemonic := []byte("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	password := []byte("my-secure-password-123")

	// Encrypt using Argon2id
	vault, err := EncryptMnemonic(mnemonic, password)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if vault.KDF.Algorithm != "argon2id" {
		t.Errorf("Expected KDF algorithm to be argon2id, got %s", vault.KDF.Algorithm)
	}
	if vault.KDF.Memory != KDFMemory {
		t.Errorf("Expected memory to be %d, got %d", KDFMemory, vault.KDF.Memory)
	}
	if vault.KDF.Iterations != KDFTime {
		t.Errorf("Expected iterations to be %d, got %d", KDFTime, vault.KDF.Iterations)
	}
	if vault.KDF.Parallelism != KDFThreads {
		t.Errorf("Expected parallelism to be %d, got %d", KDFThreads, vault.KDF.Parallelism)
	}

	// Decrypt
	decrypted, err := vault.DecryptMnemonic(password)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(mnemonic, decrypted) {
		t.Errorf("Decrypted mnemonic does not match original. Got: %s", string(decrypted))
	}

	// Decrypt with wrong password
	_, err = vault.DecryptMnemonic([]byte("wrong-password"))
	if err == nil {
		t.Error("Expected decryption to fail with wrong password, but it succeeded")
	}
}

func TestBuildCryptoAccountUR(t *testing.T) {
	masterFP := uint32(0x37b5eed4)
	pubKeyBytes := make([]byte, 33)
	pubKeyBytes[0] = 0x03
	chainCode := make([]byte, 32)
	parentFPBytes := []byte{0x0d, 0x5d, 0xfb, 0xd7}

	// Test Mainnet
	urMainnet := BuildCryptoAccountUR(masterFP, pubKeyBytes, chainCode, parentFPBytes, false, 0)
	if !strings.HasPrefix(urMainnet, "UR:CRYPTO-ACCOUNT/") {
		t.Errorf("Expected UR to start with UR:CRYPTO-ACCOUNT/, got %s", urMainnet)
	}

	// Test Testnet
	urTestnet := BuildCryptoAccountUR(masterFP, pubKeyBytes, chainCode, parentFPBytes, true, 1)
	if !strings.HasPrefix(urTestnet, "UR:CRYPTO-ACCOUNT/") {
		t.Errorf("Expected UR to start with UR:CRYPTO-ACCOUNT/, got %s", urTestnet)
	}
}

func TestBytewordsMinimalTable(t *testing.T) {
	for i, word := range bytewordsMinimalTable {
		if len(word) != 2 {
			t.Errorf("Word at index %d has invalid length: %q", i, word)
		}
		for _, char := range word {
			if char < 'A' || char > 'Z' {
				t.Errorf("Word at index %d has non-uppercase character: %q", i, word)
			}
		}
	}
}

func TestBytewordsMinimalEncodingDecoding(t *testing.T) {
	testPayload := []byte{0x00, 0x1f, 0x7f, 0x80, 0xff, 0xab, 0xcd}
	encoded := encodeBytewordsMinimal(testPayload)
	decoded, err := decodeBytewordsMinimal(encoded)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}
	if !bytes.Equal(testPayload, decoded) {
		t.Errorf("Bytewords roundtrip failed: got %x, want %x", decoded, testPayload)
	}
}

func TestCBORUintEncoding(t *testing.T) {
	tests := []struct {
		val      uint32
		expected []byte
	}{
		{0, []byte{0x00}},
		{23, []byte{0x17}},
		{24, []byte{0x18, 0x18}},
		{255, []byte{0x18, 0xff}},
		{256, []byte{0x19, 0x01, 0x00}},
		{65535, []byte{0x19, 0xff, 0xff}},
		{65536, []byte{0x1a, 0x00, 0x01, 0x00, 0x00}},
	}

	for _, tc := range tests {
		res := encodeCBORUint(tc.val)
		if !bytes.Equal(res, tc.expected) {
			t.Errorf("CBOR uint encoding failed for %d: got %x, want %x", tc.val, res, tc.expected)
		}
	}
}

func TestCBORByteString(t *testing.T) {
	data := []byte{1, 2, 3}
	res := encodeCBORByteString(data)
	if !bytes.Equal(res, []byte{0x43, 1, 2, 3}) {
		t.Errorf("CBOR byte string encoding failed: got %x", res)
	}
}

func TestPSBTSecureSigning(t *testing.T) {
	// 1. Setup mock keys
	mnemonic := []byte("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	seed := bip.MnemonicToSeed(mnemonic, nil)
	netParams := &chaincfg.TestNet3Params

	masterKey, err := hdkeychain.NewMaster(seed, netParams)
	if err != nil {
		t.Fatalf("Failed to create master key: %v", err)
	}
	defer masterKey.Zero()

	masterPub, err := masterKey.ECPubKey()
	if err != nil {
		t.Fatalf("Failed to get master pubkey: %v", err)
	}
	derivedMasterFP := binary.LittleEndian.Uint32(btcutil.Hash160(masterPub.SerializeCompressed())[:4])

	// Derive input key (m/84'/1'/0'/0/0)
	inputPath := []uint32{
		84 + hdkeychain.HardenedKeyStart,
		1 + hdkeychain.HardenedKeyStart,
		0 + hdkeychain.HardenedKeyStart,
		0,
		0,
	}
	inputKey, err := derivePath(masterKey, inputPath)
	if err != nil {
		t.Fatalf("Failed to derive input key: %v", err)
	}
	inputPub, err := inputKey.ECPubKey()
	inputPubBytes := inputPub.SerializeCompressed()

	// Derive change key (m/84'/1'/0'/1/0)
	changePath := []uint32{
		84 + hdkeychain.HardenedKeyStart,
		1 + hdkeychain.HardenedKeyStart,
		0 + hdkeychain.HardenedKeyStart,
		1,
		0,
	}
	changeKey, err := derivePath(masterKey, changePath)
	if err != nil {
		t.Fatalf("Failed to derive change key: %v", err)
	}
	changePub, err := changeKey.ECPubKey()
	changePubHash := btcutil.Hash160(changePub.SerializeCompressed())
	changeAddr, err := btcutil.NewAddressWitnessPubKeyHash(changePubHash, netParams)
	if err != nil {
		t.Fatalf("Failed to create change address: %v", err)
	}
	changePkScript, err := txscript.PayToAddrScript(changeAddr)
	if err != nil {
		t.Fatalf("Failed to create change pkscript: %v", err)
	}

	// 2. Construct valid unsigned transaction
	tx := wire.NewMsgTx(2)
	// Add one input
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{
		Hash:  chainhash.Hash{},
		Index: 0,
	}, nil, nil))
	// Add one change output
	tx.AddTxOut(wire.NewTxOut(100000, changePkScript))

	// 3. Create PSBT
	p, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		t.Fatalf("Failed to create PSBT: %v", err)
	}

	// Populate input BIP32 derivation
	p.Inputs[0].Bip32Derivation = []*psbt.Bip32Derivation{
		{
			PubKey:               inputPubBytes,
			MasterKeyFingerprint: derivedMasterFP,
			Bip32Path:            inputPath,
		},
	}
	// Add witness UTXO for the input (value = 150000 sat)
	inputPubHash := btcutil.Hash160(inputPubBytes)
	inputAddr, err := btcutil.NewAddressWitnessPubKeyHash(inputPubHash, netParams)
	if err != nil {
		t.Fatalf("Failed to create input address: %v", err)
	}
	inputPkScript, err := txscript.PayToAddrScript(inputAddr)
	if err != nil {
		t.Fatalf("Failed to create input pkscript: %v", err)
	}
	p.Inputs[0].WitnessUtxo = &wire.TxOut{
		Value:    150000,
		PkScript: inputPkScript,
	}
	
	// Create a dummy NonWitnessUtxo to pass the security check
	dummyTx := wire.NewMsgTx(2)
	dummyTx.AddTxOut(&wire.TxOut{
		Value:    150000,
		PkScript: inputPkScript,
	})
	p.Inputs[0].NonWitnessUtxo = dummyTx
	p.UnsignedTx.TxIn[0].PreviousOutPoint.Hash = dummyTx.TxHash()
	p.UnsignedTx.TxIn[0].PreviousOutPoint.Index = 0

	// Populate output BIP32 derivation
	p.Outputs[0].Bip32Derivation = []*psbt.Bip32Derivation{
		{
			PubKey:               changePub.SerializeCompressed(),
			MasterKeyFingerprint: derivedMasterFP,
			Bip32Path:            changePath,
		},
	}

	// Test case A: Valid change output (should succeed)
	signedCount, err := signTransactionInputs(p, masterKey, netParams, true, 0)
	if err != nil {
		t.Errorf("Signing valid PSBT failed: %v", err)
	}
	if signedCount != 1 {
		t.Errorf("Expected 1 signed input, got %d", signedCount)
	}

	// Clear signature for next test
	p.Inputs[0].PartialSigs = nil

	// Test case B: Fake Change Output (attack scenario)
	// We change the output script to a dummy/attacker pkscript
	attackerPkScript := []byte{0x00, 0x14, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef}
	p.UnsignedTx.TxOut[0].PkScript = attackerPkScript

	_, err = signTransactionInputs(p, masterKey, netParams, true, 0)
	if err == nil {
		t.Error("Expected Fake Change transaction to fail, but it succeeded")
	} else if !strings.Contains(err.Error(), "CRITICAL SECURITY WARNING") {
		t.Errorf("Expected critical security warning error, got: %v", err)
	}

	// Test case C: Sighash Manipulation Attack (SIGHASH_NONE)
	// We restore the change output, but manipulate the requested SighashType
	p.UnsignedTx.TxOut[0].PkScript = changePkScript // Restore valid script
	p.Inputs[0].SighashType = txscript.SigHashNone

	_, err = signTransactionInputs(p, masterKey, netParams, true, 0)
	if err == nil {
		t.Error("Expected Sighash Manipulation transaction to fail, but it succeeded")
	} else if !strings.Contains(err.Error(), "CRITICAL SECURITY WARNING") || !strings.Contains(err.Error(), "dangerous SighashType") {
		t.Errorf("Expected Sighash security warning error, got: %v", err)
	}
}

