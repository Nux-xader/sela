package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"strings"

	"github.com/Nux-xader/sela/sela-vault/util"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// isChangeOutput checks if an output is a change address belonging to our derivation path.
func isChangeOutput(outDerivs []*psbt.Bip32Derivation, masterFP uint32, isTestnet bool, accountIdx uint32) (bool, uint32) {
	coinType := uint32(0)
	if isTestnet {
		coinType = 1
	}
	purpose := uint32(84)

	for _, d := range outDerivs {
		if d == nil {
			continue
		}
		if d.MasterKeyFingerprint == masterFP && len(d.Bip32Path) == 5 {
			if d.Bip32Path[0] == purpose+hdkeychain.HardenedKeyStart &&
				d.Bip32Path[1] == coinType+hdkeychain.HardenedKeyStart &&
				d.Bip32Path[2] == accountIdx+hdkeychain.HardenedKeyStart &&
				d.Bip32Path[3] == 1 { // 1 means internal/change chain
				return true, d.Bip32Path[4]
			}
		}
	}
	return false, 0
}

// findMasterFingerprint seeks the master fingerprint in PSBT inputs and outputs.
func findMasterFingerprint(p *psbt.Packet, isTestnet bool, accountIdx uint32) (uint32, bool) {
	coinType := uint32(0)
	if isTestnet {
		coinType = 1
	}
	purpose := uint32(84)

	// Seek in inputs
	for _, in := range p.Inputs {
		for _, d := range in.Bip32Derivation {
			if d == nil {
				continue
			}
			if len(d.Bip32Path) == 5 &&
				d.Bip32Path[0] == purpose+hdkeychain.HardenedKeyStart &&
				d.Bip32Path[1] == coinType+hdkeychain.HardenedKeyStart &&
				d.Bip32Path[2] == accountIdx+hdkeychain.HardenedKeyStart {
				return d.MasterKeyFingerprint, true
			}
		}
	}

	// Seek in outputs
	for _, out := range p.Outputs {
		for _, d := range out.Bip32Derivation {
			if d == nil {
				continue
			}
			if len(d.Bip32Path) == 5 &&
				d.Bip32Path[0] == purpose+hdkeychain.HardenedKeyStart &&
				d.Bip32Path[1] == coinType+hdkeychain.HardenedKeyStart &&
				d.Bip32Path[2] == accountIdx+hdkeychain.HardenedKeyStart {
				return d.MasterKeyFingerprint, true
			}
		}
	}

	return 0, false
}

// derivePath derives the key at the given path starting from the master key.
// It uses a helper to isolate scope so that deferred zeroing of intermediate keys runs immediately.
func derivePath(masterKey *hdkeychain.ExtendedKey, path []uint32) (*hdkeychain.ExtendedKey, error) {
	key := masterKey
	for i, idx := range path {
		nextKey, err := key.Derive(idx)
		if err != nil {
			if i > 0 {
				key.Zero()
			}
			return nil, err
		}
		// If it's not the final leaf key, we defer zeroing the intermediate keys.
		// Since we reassigned key, we can zero the old one immediately except for the masterKey.
		if i > 0 {
			key.Zero()
		}
		key = nextKey
	}
	return key, nil
}

// parsePSBTInput parses the PSBT input, supporting both Base64 and UR:CRYPTO-PSBT formats.
func parsePSBTInput(input []byte) (*psbt.Packet, error) {
	input = bytes.TrimSpace(input)
	if len(input) == 0 {
		return nil, errors.New("empty PSBT input")
	}

	inputStr := string(input)
	var psbtBytes []byte
	var err error

	if strings.HasPrefix(strings.ToLower(inputStr), "ur:crypto-psbt/") {
		parts := strings.Split(inputStr, "/")
		if len(parts) < 2 {
			return nil, errors.New("invalid UR format")
		}
		bytewordsStr := strings.ToUpper(parts[1])
		cborPayload, err := decodeBytewordsMinimal(bytewordsStr)
		if err != nil {
			return nil, fmt.Errorf("decoding UR Bytewords: %w", err)
		}
		defer util.WipeBytes(cborPayload)

		if len(cborPayload) < 4 {
			return nil, errors.New("UR payload too short")
		}

		cborBytes := cborPayload[:len(cborPayload)-4]
		expectedChecksum := binary.BigEndian.Uint32(cborPayload[len(cborPayload)-4:])
		if crc32.ChecksumIEEE(cborBytes) != expectedChecksum {
			return nil, errors.New("invalid checksum in UR payload")
		}

		// Look for PSBT magic bytes: 70 73 62 74 ff
		magic := []byte{0x70, 0x73, 0x62, 0x74, 0xff}
		idx := bytes.Index(cborBytes, magic)
		if idx == -1 {
			return nil, errors.New("could not find PSBT magic bytes in payload")
		}
		psbtBytes = make([]byte, len(cborBytes[idx:]))
		copy(psbtBytes, cborBytes[idx:])
	} else {
		psbtBytes, err = base64.StdEncoding.DecodeString(inputStr)
		if err != nil {
			return nil, fmt.Errorf("decoding Base64: %w", err)
		}
	}

	packet, err := psbt.NewFromRawBytes(bytes.NewReader(psbtBytes), false)
	util.WipeBytes(psbtBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing PSBT structure: %w", err)
	}

	return packet, nil
}

// TxDetails stores extracted information from PSBT for terminal verification.
type TxDetails struct {
	TotalInput    int64
	TotalOutput   int64
	RecipientOuts []string
	ChangeOuts    []string
	MinerFee      int64
	FeeRate       float64
}

// extractTxDetails parses and extracts verification information from a PSBT packet.
func extractTxDetails(p *psbt.Packet, isTestnet bool, accountIdx uint32) (*TxDetails, error) {
	var netParams *chaincfg.Params
	if isTestnet {
		netParams = &chaincfg.TestNet3Params
	} else {
		netParams = &chaincfg.MainNetParams
	}

	var totalInput int64 = 0
	for inIdx, in := range p.Inputs {
		if in.WitnessUtxo != nil {
			if in.NonWitnessUtxo != nil {
				// Prevent Fake WitnessUtxo Amount Attack (BIP-143 Vulnerability)
				prevOutIndex := p.UnsignedTx.TxIn[inIdx].PreviousOutPoint.Index
				if uint32(len(in.NonWitnessUtxo.TxOut)) <= prevOutIndex {
					return nil, errors.New("CRITICAL SECURITY WARNING: NonWitnessUtxo does not contain the referenced output!")
				}
				if in.NonWitnessUtxo.TxOut[prevOutIndex].Value != in.WitnessUtxo.Value {
					return nil, fmt.Errorf("CRITICAL SECURITY WARNING: Fake WitnessUtxo Amount Attack detected! Reported %d but real value is %d", in.WitnessUtxo.Value, in.NonWitnessUtxo.TxOut[prevOutIndex].Value)
				}
				if in.NonWitnessUtxo.TxHash() != p.UnsignedTx.TxIn[inIdx].PreviousOutPoint.Hash {
					return nil, errors.New("CRITICAL SECURITY WARNING: Fake NonWitnessUtxo provided! TxHash does not match Outpoint!")
				}
			} else {
				// Hybrid Mode: Warn instead of hard-failing to allow compact base64/QR usage
				fmt.Printf("\033[31m⚠️  SECURITY WARNING: Missing NonWitnessUtxo for SegWit input %d! Amount cannot be verified.\033[0m\n", inIdx)
			}
			if in.WitnessUtxo.Value < 0 || in.WitnessUtxo.Value > 21000000*100000000 {
				return nil, errors.New("CRITICAL SECURITY WARNING: Invalid WitnessUtxo value (negative or exceeds max supply)!")
			}
			totalInput += in.WitnessUtxo.Value
		} else {
			return nil, errors.New("non-witness inputs are not supported (BIP-84 only)")
		}
	}

	if totalInput < 0 || totalInput > 21000000*100000000 {
		return nil, errors.New("CRITICAL SECURITY WARNING: Total input value exceeds maximum possible supply!")
	}

	var totalOutput int64 = 0
	var recipientOuts []string
	var changeOuts []string

	masterFP, _ := findMasterFingerprint(p, isTestnet, accountIdx)
	coinType := uint32(0)
	if isTestnet {
		coinType = 1
	}

	for outIdx, out := range p.UnsignedTx.TxOut {
		if out.Value < 0 || out.Value > 21000000*100000000 {
			return nil, errors.New("CRITICAL SECURITY WARNING: Invalid Output value (negative or exceeds max supply)!")
		}
		totalOutput += out.Value
		if totalOutput < 0 || totalOutput > 21000000*100000000 {
			return nil, errors.New("CRITICAL SECURITY WARNING: Total output value exceeds maximum possible supply!")
		}
		valBTC := float64(out.Value) / 1e8

		isChange, changeIdx := isChangeOutput(p.Outputs[outIdx].Bip32Derivation, masterFP, isTestnet, accountIdx)
		if isChange {
			changeOuts = append(changeOuts, fmt.Sprintf("  Change:     %.8f BTC -> Sent back to your wallet (m/84'/%d'/%d'/1/%d)", valBTC, coinType, accountIdx, changeIdx))
		} else {
			var addrStr string = "unknown"
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(out.PkScript, netParams)
			if err == nil && len(addrs) > 0 {
				addrStr = addrs[0].EncodeAddress()
			}
			recipientOuts = append(recipientOuts, fmt.Sprintf("  Recipient:  %.8f BTC -> %s (4-4-4 Check Required!)", valBTC, addrStr))
		}
	}

	minerFee := totalInput - totalOutput
	feeRate := float64(minerFee) / float64(p.UnsignedTx.SerializeSize())

	return &TxDetails{
		TotalInput:    totalInput,
		TotalOutput:   totalOutput,
		RecipientOuts: recipientOuts,
		ChangeOuts:    changeOuts,
		MinerFee:      minerFee,
		FeeRate:       feeRate,
	}, nil
}

// getMasterFingerprint calculates the BIP-32 4-byte master fingerprint.
func getMasterFingerprint(masterKey *hdkeychain.ExtendedKey) (uint32, error) {
	masterPub, err := masterKey.ECPubKey()
	if err != nil {
		return 0, fmt.Errorf("getting master public key: %w", err)
	}
	// btcutil/psbt parses the fingerprint using Little Endian.
	return binary.LittleEndian.Uint32(btcutil.Hash160(masterPub.SerializeCompressed())[:4]), nil
}

// verifyOwnership ensures that the PSBT contains inputs/outputs matching our seed's fingerprint.
func verifyOwnership(p *psbt.Packet, derivedMasterFP uint32, isTestnet bool, accountIdx uint32) error {
	expectedFP, foundFP := findMasterFingerprint(p, isTestnet, accountIdx)
	if foundFP && derivedMasterFP != expectedFP {
		return errors.New("master fingerprint mismatch: this vault/seed does not own the keys in the transaction")
	}
	return nil
}

// verifyChangeAddresses strictly verifies all outputs marked as change to prevent "Fake Change Address" attacks.
func verifyChangeAddresses(p *psbt.Packet, masterKey *hdkeychain.ExtendedKey, derivedMasterFP uint32, netParams *chaincfg.Params, isTestnet bool, accountIdx uint32) error {
	coinType := uint32(0)
	if isTestnet {
		coinType = 1
	}
	purpose := uint32(84)

	for outIdx, out := range p.UnsignedTx.TxOut {
		isChange, changeIdx := isChangeOutput(p.Outputs[outIdx].Bip32Derivation, derivedMasterFP, isTestnet, accountIdx)
		if isChange {
			changePath := []uint32{
				purpose + hdkeychain.HardenedKeyStart,
				coinType + hdkeychain.HardenedKeyStart,
				accountIdx + hdkeychain.HardenedKeyStart,
				1,         // change chain
				changeIdx, // child index
			}
			changeKey, err := derivePath(masterKey, changePath)
			if err != nil {
				return fmt.Errorf("deriving change key for verification: %w", err)
			}

			changePub, err := changeKey.ECPubKey()
			changeKey.Zero() // Wipe intermediate key immediately
			if err != nil {
				return fmt.Errorf("getting change public key for verification: %w", err)
			}

			changePubHash := btcutil.Hash160(changePub.SerializeCompressed())
			witnessAddr, err := btcutil.NewAddressWitnessPubKeyHash(changePubHash, netParams)
			if err != nil {
				return fmt.Errorf("creating witness address for change verification: %w", err)
			}
			expectedPkScript, err := txscript.PayToAddrScript(witnessAddr)
			if err != nil {
				return fmt.Errorf("creating pay-to-addr script for change verification: %w", err)
			}

			if !bytes.Equal(out.PkScript, expectedPkScript) {
				return fmt.Errorf("CRITICAL SECURITY WARNING: Change address script mismatch for output %d! Expected address for path m/84'/%d'/%d'/1/%d does not match actual output script. Aborting signing to prevent loss of funds", outIdx, coinType, accountIdx, changeIdx)
			}

			// Prevent Fake Change Address via manipulated Bip32Derivation PubKey
			if !bytes.Equal(p.Outputs[outIdx].Bip32Derivation[0].PubKey, changePub.SerializeCompressed()) {
				return fmt.Errorf("CRITICAL SECURITY WARNING: Change address public key mismatch! The coordinator is lying about the change address pubkey.")
			}
		}
	}
	return nil
}

// createSigHashFetcher builds the prevOut fetcher needed for signing SegWit inputs.
func createSigHashFetcher(p *psbt.Packet) *txscript.TxSigHashes {
	prevOuts := make(map[wire.OutPoint]*wire.TxOut)
	for i, txIn := range p.UnsignedTx.TxIn {
		in := p.Inputs[i]
		if in.WitnessUtxo != nil {
			prevOuts[txIn.PreviousOutPoint] = in.WitnessUtxo
		} else if in.NonWitnessUtxo != nil && int(txIn.PreviousOutPoint.Index) < len(in.NonWitnessUtxo.TxOut) {
			prevOuts[txIn.PreviousOutPoint] = in.NonWitnessUtxo.TxOut[txIn.PreviousOutPoint.Index]
		}
	}
	fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	return txscript.NewTxSigHashes(p.UnsignedTx, fetcher)
}

// signSingleInput attempts to sign a single PSBT input if it belongs to our seed.
func signSingleInput(p *psbt.Packet, inputIdx int, masterKey *hdkeychain.ExtendedKey, derivedMasterFP uint32, sigHashes *txscript.TxSigHashes, netParams *chaincfg.Params, isTestnet bool, accountIdx uint32) (bool, error) {
	in := p.Inputs[inputIdx]

	// CRITICAL SECURITY: We ONLY allow SIGHASH_ALL. Allowing SIGHASH_NONE or SIGHASH_SINGLE
	// would let a malicious Sparrow Wallet take our signature and attach it to a transaction
	// that pays a hacker instead of our intended recipients.
	if in.SighashType != 0 && in.SighashType != txscript.SigHashAll {
		return false, fmt.Errorf("CRITICAL SECURITY WARNING: Input %d requests dangerous SighashType (%v). Only SIGHASH_ALL is permitted to prevent transaction hijacking", inputIdx, in.SighashType)
	}

	coinType := uint32(0)
	if isTestnet {
		coinType = 1
	}
	purpose := uint32(84)

	for _, d := range in.Bip32Derivation {
		if d == nil {
			continue
		}
		if d.MasterKeyFingerprint == derivedMasterFP {
			if len(d.Bip32Path) != 5 {
				return false, fmt.Errorf("CRITICAL SECURITY WARNING: Invalid BIP32 path length for our fingerprint. Expected 5, got %d", len(d.Bip32Path))
			}
			if d.Bip32Path[0] != purpose+hdkeychain.HardenedKeyStart ||
				d.Bip32Path[1] != coinType+hdkeychain.HardenedKeyStart ||
				d.Bip32Path[2] != accountIdx+hdkeychain.HardenedKeyStart {
				return false, fmt.Errorf("CRITICAL SECURITY WARNING: BIP Mismatch Attack detected! The coordinator requested signing for an unauthorized derivation path: m/%d'/%d'/%d'. Sela Vault only authorizes m/84'/%d'/%d'.", d.Bip32Path[0]-hdkeychain.HardenedKeyStart, d.Bip32Path[1]-hdkeychain.HardenedKeyStart, d.Bip32Path[2]-hdkeychain.HardenedKeyStart, coinType, accountIdx)
			}

			signed := false
			err := func() error {
				leafKey, err := derivePath(masterKey, d.Bip32Path)
				if err != nil {
					return fmt.Errorf("deriving input private key: %w", err)
				}
				defer leafKey.Zero()

				privKey, err := leafKey.ECPrivKey()
				if err != nil {
					return fmt.Errorf("getting EC private key: %w", err)
				}
				defer privKey.Zero()

				pubKey, err := leafKey.ECPubKey()
				if err != nil {
					return fmt.Errorf("getting EC public key: %w", err)
				}

				if !bytes.Equal(pubKey.SerializeCompressed(), d.PubKey) {
					return nil // Not a match, skip silently
				}

				pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
				addr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, netParams)
				if err != nil {
					return fmt.Errorf("creating address from pubkeyhash: %w", err)
				}
				subScript, err := txscript.PayToAddrScript(addr)
				if err != nil {
					return fmt.Errorf("creating subscript: %w", err)
				}

				sigWithHashType, err := txscript.RawTxInWitnessSignature(p.UnsignedTx, sigHashes, inputIdx, in.WitnessUtxo.Value, subScript, txscript.SigHashAll, privKey)
				if err != nil {
					return fmt.Errorf("creating witness signature: %w", err)
				}

				p.Inputs[inputIdx].PartialSigs = append(p.Inputs[inputIdx].PartialSigs, &psbt.PartialSig{
					PubKey:    pubKey.SerializeCompressed(),
					Signature: sigWithHashType,
				})
				signed = true
				return nil
			}()

			if err != nil {
				return false, err
			}
			if signed {
				return true, nil
			}
		}
	}
	return false, nil
}

// signTransactionInputs is the main entry point for signing a PSBT.
// It orchestrates security verification and delegates signing of inputs.
func signTransactionInputs(p *psbt.Packet, masterKey *hdkeychain.ExtendedKey, netParams *chaincfg.Params, isTestnet bool, accountIdx uint32) (int, error) {
	// Get the 4-byte master fingerprint for our seed
	derivedMasterFP, err := getMasterFingerprint(masterKey)
	if err != nil {
		return 0, err
	}

	// Ensure this PSBT actually belongs to us
	if err := verifyOwnership(p, derivedMasterFP, isTestnet, accountIdx); err != nil {
		return 0, err
	}

	// Reject Malformed Parser Bombs (Nil/Empty Derivations)
	for _, in := range p.Inputs {
		for _, d := range in.Bip32Derivation {
			if d == nil || len(d.Bip32Path) == 0 {
				return 0, errors.New("CRITICAL SECURITY WARNING: Malformed PSBT! Nil or empty Bip32Derivation detected.")
			}
		}
	}
	for _, out := range p.Outputs {
		for _, d := range out.Bip32Derivation {
			if d == nil || len(d.Bip32Path) == 0 {
				return 0, errors.New("CRITICAL SECURITY WARNING: Malformed PSBT! Nil or empty Bip32Derivation detected.")
			}
		}
	}

	// Prevent OOM DoS Bomb and Dust Spam Attacks by enforcing limits
	if len(p.Inputs) > 20 || len(p.UnsignedTx.TxOut) > 20 {
		return 0, fmt.Errorf("CRITICAL SECURITY WARNING: Transaction too complex! Sela Vault strictly limits transactions to 20 inputs and 20 outputs to prevent DoS/Spam attacks.")
	}

	// Extract details and perform Fee Sniping check
	txDetails, err := extractTxDetails(p, isTestnet, accountIdx)
	if err != nil {
		return 0, err
	}
	if txDetails.MinerFee < 0 {
		return 0, fmt.Errorf("CRITICAL SECURITY WARNING: Invalid transaction detected! Total outputs exceed total inputs.")
	}
	if txDetails.MinerFee > 1000000 { // 0.01 BTC absolute maximum fee
		return 0, fmt.Errorf("CRITICAL SECURITY WARNING: Abnormally high miner fee detected (%.8f BTC)! Possible Fee Sniping Attack. Aborting signing.", float64(txDetails.MinerFee)/1e8)
	}

	// Prevent LockTime Hostage Attack
	if p.UnsignedTx.LockTime > 0 {
		if p.UnsignedTx.LockTime < 500000000 {
			if p.UnsignedTx.LockTime > 5000000 {
				return 0, fmt.Errorf("CRITICAL SECURITY WARNING: LockTime Hostage Attack detected! Block height %d is too far in the future.", p.UnsignedTx.LockTime)
			}
		} else {
			if p.UnsignedTx.LockTime > 4000000000 {
				return 0, fmt.Errorf("CRITICAL SECURITY WARNING: LockTime Hostage Attack detected! Timestamp %d is too far in the future.", p.UnsignedTx.LockTime)
			}
		}
	}

	// Prevent Fake Change Address attacks (crucial security check)
	if err := verifyChangeAddresses(p, masterKey, derivedMasterFP, netParams, isTestnet, accountIdx); err != nil {
		return 0, err
	}

	// Create the Sighash Fetcher (needed for SegWit transaction hashing)
	sigHashes := createSigHashFetcher(p)

	// Sign all inputs that belong to us
	signedCount := 0
	for i := range p.Inputs {
		signed, err := signSingleInput(p, i, masterKey, derivedMasterFP, sigHashes, netParams, isTestnet, accountIdx)
		if err != nil {
			return 0, err
		}
		if signed {
			signedCount++
		}
	}

	return signedCount, nil
}
