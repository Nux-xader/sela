package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nux-xader/sela/sela-vault/bip"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// RPCClient simplifies bitcoind RPC calls
type RPCClient struct {
	url  string
	user string
	pass string
}

func newRPCClient(url, user, pass string) *RPCClient {
	return &RPCClient{url: url, user: user, pass: pass}
}

func (c *RPCClient) Call(method string, params []any) (json.RawMessage, error) {
	reqBody := map[string]any{
		"jsonrpc": "1.0",
		"id":      "sela",
		"method":  method,
		"params":  params,
	}
	bodyBytes, _ := json.Marshal(reqBody)
	req, err := http.NewRequest("POST", c.url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.user, c.pass)
	req.Header.Set("Content-Type", "text/plain")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var res map[string]json.RawMessage
	if err := json.Unmarshal(respBytes, &res); err != nil {
		return nil, fmt.Errorf("RPC Parse Error: %v. Raw: %s", err, string(respBytes))
	}

	if errRaw, ok := res["error"]; ok && string(errRaw) != "null" {
		return nil, fmt.Errorf("RPC Error: %s", string(errRaw))
	}

	return res["result"], nil
}

var rpcFundingMutex sync.Mutex

// txCounter tracks how many funding rounds have happened to trigger periodic maturation mining
var txCounter atomic.Int64

var (
	cachedWordlist     []string
	cachedWordlistOnce sync.Once
)

func findBattleWordlistPath() string {
	candidates := []string{
		"../bip-39-english.txt",
		"bip-39-english.txt",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func getBIP39Words() []string {
	cachedWordlistOnce.Do(func() {
		if path := findBattleWordlistPath(); path != "" {
			words, err := bip.LoadWordlist(path)
			if err == nil && len(words) == 2048 {
				cachedWordlist = words
			}
		}
	})
	return cachedWordlist
}

// generateRandomMnemonic creates a mock mnemonic using real BIP-39 words when available.
func generateRandomMnemonic(wordCount int) string {
	wordsPool := getBIP39Words()
	var words []string
	if len(wordsPool) == 2048 {
		for range wordCount {
			words = append(words, wordsPool[rand.Intn(len(wordsPool))])
		}
	} else {
		for range wordCount {
			words = append(words, fmt.Sprintf("word%d", rand.Intn(100000)))
		}
	}
	return strings.Join(words, " ")
}

func TestRegtestBattle(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Regtest battle in short mode.")
	}

	rpcUser := os.Getenv("BTC_RPC_USER")
	rpcPass := os.Getenv("BTC_RPC_PASS")
	rpcURL := os.Getenv("BTC_RPC_URL")
	if rpcURL == "" {
		rpcURL = "http://127.0.0.1:18443/wallet/faucet"
	}

	if rpcUser == "" || rpcPass == "" {
		t.Skip("Skipping Regtest battle: BTC_RPC_USER and BTC_RPC_PASS must be set.")
	}

	rpc := newRPCClient(rpcURL, rpcUser, rpcPass)

	// 1. Ensure node is ready and we have funds
	_, err := rpc.Call("getblockchaininfo", []any{})
	if err != nil {
		t.Fatalf("Failed to connect to bitcoind: %v", err)
	}

	// Make sure a wallet is loaded for the faucet
	var wallets []string
	walletsRes, _ := rpc.Call("listwallets", []any{})
	json.Unmarshal(walletsRes, &wallets)
	if len(wallets) == 0 {
		_, err = rpc.Call("createwallet", []any{"faucet"})
		if err != nil {
			t.Fatalf("Failed to create faucet wallet: %v", err)
		}
	}

	// 2. Concurrency Configuration
	numWorkers := runtime.NumCPU()
	if workerEnv := os.Getenv("SELA_WORKERS"); workerEnv != "" {
		if w, err := strconv.Atoi(workerEnv); err == nil && w > 0 {
			numWorkers = w
		}
	}

	battleDepth := 1000 // default 1000 total permutations
	if envDepth := os.Getenv("SELA_BATTLE_DEPTH"); envDepth != "" {
		if d, err := strconv.Atoi(envDepth); err == nil && d > 0 {
			battleDepth = d
		}
	}

	// Calculate how many blocks we need to fund the entire battle depth.
	// 1 block = 50 BTC. Each scenario might spend up to 100 BTC (2 blocks).
	// We need 100.000 blocks just for maturity.
	blocksToMine := 100_000 + (battleDepth * 5)

	// Generate blocks to ensure PLENTY of mature funds
	var faucetAddrStr string
	addrRes, _ := rpc.Call("getnewaddress", []any{})
	json.Unmarshal(addrRes, &faucetAddrStr)
	rpc.Call("generatetoaddress", []any{blocksToMine, faucetAddrStr})

	t.Logf("Regtest is ready! Faucet is funded with %d blocks. Preparing Matrix of %d Paths...", blocksToMine, battleDepth)

	// 3. Deterministic Shuffle of Paths
	allPaths := make([]uint32, battleDepth)
	for i := 0; i < battleDepth; i++ {
		allPaths[i] = uint32(i)
	}
	rand.Shuffle(len(allPaths), func(i, j int) {
		allPaths[i], allPaths[j] = allPaths[j], allPaths[i]
	})

	var wg sync.WaitGroup
	var successCounts [17]int32
	var failCounts [17]int32
	var completedTx int32

	scenarioNames := []string{
		"Valid Transaction",
		"Sighash Attack",
		"Fake Change Attack",
		"Ownership Hijacking",
		"Fee Sniping (Dust Output)",
		"BIP Mismatch Attack",
		"Network Mismatch Attack",
		"Combined Attack (Sighash+Change)",
		"Fake WitnessUtxo Amount Attack",
		"RBF Hijacking Attack",
		"Dust Spam Attack",
		"Change Omission Attack",
		"OOM DoS Bomb Attack",
		"Malformed Parser Bomb (Nil/OOB)",
		"LockTime Hostage Attack",
		"Deterministic Signature Anti-Klepto Test",
		"Integer Overflow Fee Attack",
	}

	start := time.Now()

	chunkSize := battleDepth / numWorkers
	if chunkSize == 0 {
		chunkSize = 1
		numWorkers = battleDepth
	}

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)

		startIdx := w * chunkSize
		endIdx := startIdx + chunkSize
		if w == numWorkers-1 {
			endIdx = len(allPaths)
		}

		workerPaths := allPaths[startIdx:endIdx]

		go func(workerID int, paths []uint32) {
			defer wg.Done()
			for i, pPath := range paths {
				scenarioIdx, err := executeRandomScenario(rpc, pPath)
				if err != nil {
					if atomic.LoadInt32(&failCounts[scenarioIdx]) <= 3 {
						t.Errorf("\n❌ Worker %d Failed on TX %d [%s]:\n   %v", workerID, i, scenarioNames[scenarioIdx], err)
					}
					atomic.AddInt32(&failCounts[scenarioIdx], 1)
				} else {
					atomic.AddInt32(&successCounts[scenarioIdx], 1)
				}
				atomic.AddInt32(&completedTx, 1)

				// We no longer mine blocks here because it is done securely inside the mutex
			}
		}(w, workerPaths)
	}

	doneChan := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneChan)
	}()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	printProgress := func(completed int, total int, start time.Time) {
		percent := float64(completed) / float64(total) * 100
		elapsed := time.Since(start)

		var eta time.Duration
		if completed > 0 {
			timePerTx := elapsed / time.Duration(completed)
			eta = timePerTx * time.Duration(total-completed)
		}

		barWidth := 40
		filled := int(float64(barWidth) * float64(completed) / float64(total))
		bar := strings.Repeat("█", filled) + strings.Repeat("-", barWidth-filled)

		fmt.Printf("\r[%s] %.1f%% (%d/%d) | Elapsed: %v | ETA: %v  ", bar, percent, completed, total, elapsed.Round(time.Second), eta.Round(time.Second))
	}

ProgressLoop:
	for {
		select {
		case <-doneChan:
			c := int(atomic.LoadInt32(&completedTx))
			printProgress(c, battleDepth, start)
			fmt.Println()
			break ProgressLoop
		case <-ticker.C:
			c := int(atomic.LoadInt32(&completedTx))
			printProgress(c, battleDepth, start)
		}
	}
	elapsed := time.Since(start)

	totalFail := int32(0)
	t.Logf("\n\n=========================================")
	t.Logf("🛡️  BATTLE TEST COMBAT REPORT (%.2fs)", elapsed.Seconds())
	t.Logf("Speed: %.2f TX/second", float64(battleDepth)/elapsed.Seconds())
	t.Logf("=========================================")
	for i := range scenarioNames {
		status := "✅ PERFECT"
		if failCounts[i] > 0 {
			status = "❌ BREACHED"
		}
		t.Logf("[%s] %s", status, scenarioNames[i])
		t.Logf("    Passed: %d", successCounts[i])
		t.Logf("    Failed: %d", failCounts[i])
		totalFail += failCounts[i]
	}
	t.Logf("=========================================\n")

	if totalFail > 0 {
		t.Fatalf("Battle Test Failed! %d vulnerabilities detected.", totalFail)
	}
}

func executeRandomScenario(rpc *RPCClient, primaryPath uint32) (int, error) {
	netParams := &chaincfg.RegressionNetParams

	attackScenario := rand.Intn(17) // 0 to 16

	// Random Mnemonic (12, 15, 18, 21, or 24 words)
	wordCounts := []int{12, 15, 18, 21, 24}
	mnemonic := generateRandomMnemonic(wordCounts[rand.Intn(len(wordCounts))])

	// Random Passphrase
	passphrases := []string{"", "supersecret", "emoji😎", "space password", "!!!@@@###"}
	passphrase := passphrases[rand.Intn(len(passphrases))]

	// Random Account Index up to 100,000
	accountIdx := uint32(rand.Intn(100000))

	// Topology: Random up to 20x20
	numInputs := rand.Intn(19) + 1
	numOutputs := rand.Intn(19) + 1

	seed := bip.MnemonicToSeed([]byte(mnemonic), []byte(passphrase))
	masterKey, err := hdkeychain.NewMaster(seed, netParams)
	if err != nil {
		return attackScenario, fmt.Errorf("master key error: %v", err)
	}
	defer masterKey.Zero()

	pub, _ := masterKey.ECPubKey()
	hash160 := btcutil.Hash160(pub.SerializeCompressed())
	var fingerprint []byte
	if len(hash160) >= 4 {
		fingerprint = hash160[:4]
	}

	// 2 & 3. DERIVE RECEIVE ADDRESSES & FUND THEM
	var inputs []map[string]any
	var receivePaths [][]uint32
	var recvPubs [][]byte
	totalIn := 0.0

	// Optimize funding using sendmany
	amounts := make(map[string]float64)
	addrToPathMap := make(map[string][]uint32)
	addrToPubMap := make(map[string][]byte)

	for j := 0; j < numInputs; j++ {
		addrIdx := primaryPath
		if j > 0 {
			addrIdx = uint32(rand.Intn(100000)) // Subsequent deep indices
		}

		receivePath := []uint32{84 + hdkeychain.HardenedKeyStart, 1 + hdkeychain.HardenedKeyStart, accountIdx + hdkeychain.HardenedKeyStart, 0, addrIdx}

		if attackScenario == 5 { // BIP Mismatch
			if rand.Intn(2) == 0 {
				receivePath[0] = 44 + hdkeychain.HardenedKeyStart // Legacy
			} else {
				receivePath[0] = 86 + hdkeychain.HardenedKeyStart // Taproot
			}
		}

		recvKey, _ := derivePath(masterKey, receivePath)
		recvPub, _ := recvKey.ECPubKey()
		recvKey.Zero()

		recvAddr, _ := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(recvPub.SerializeCompressed()), netParams)
		recvAddrStr := recvAddr.EncodeAddress()

		if _, exists := amounts[recvAddrStr]; exists {
			j-- // Retry on collision
			continue
		}

		rpc.Call("importaddress", []any{recvAddrStr, "", false})

		fundAmount, _ := strconv.ParseFloat(fmt.Sprintf("%.8f", 0.1+(float64(rand.Intn(40))/100.0)), 64)
		amounts[recvAddrStr] = fundAmount
		addrToPathMap[recvAddrStr] = receivePath
		addrToPubMap[recvAddrStr] = recvPub.SerializeCompressed()
		totalIn += fundAmount
	}

	var txid string

	// We MUST serialize funding to avoid Bitcoin Core's "Insufficient funds" caused by concurrent UTXO selection
	rpcFundingMutex.Lock()
	txidRes, err := rpc.Call("sendmany", []any{"", amounts})
	if err != nil {
		rpcFundingMutex.Unlock()
		return attackScenario, fmt.Errorf("sendmany failed: %v", err)
	}
	json.Unmarshal(txidRes, &txid)

	var txHex string
	for attempt := range 15 {
		txRes, txErr := rpc.Call("gettransaction", []any{txid})
		if txErr == nil && txRes != nil {
			var txData map[string]any
			json.Unmarshal(txRes, &txData)
			if h, ok := txData["hex"].(string); ok && h != "" {
				txHex = h
				break
			}
		}
		time.Sleep(time.Duration(50+attempt*50) * time.Millisecond)
	}
	if txHex == "" {
		rpcFundingMutex.Unlock()
		return attackScenario, fmt.Errorf("gettransaction failed for txid %s", txid)
	}

	// Mine a block to confirm the UTXOs and clear the mempool.
	// Every 50 transactions, mine 100 extra blocks to keep coinbase rewards mature and the
	// faucet balance replenished. This prevents "Insufficient funds" on very high depth runs.
	var faucetAddrStr string
	addrRes2, _ := rpc.Call("getnewaddress", []any{})
	json.Unmarshal(addrRes2, &faucetAddrStr)
	count := txCounter.Add(1)
	extraBlocks := 1
	if count%10 == 0 {
		extraBlocks = 101 // mine 100 maturation blocks + 1 confirmation block
	}
	rpc.Call("generatetoaddress", []any{extraBlocks, faucetAddrStr})
	rpcFundingMutex.Unlock()

	rawTxBytes, _ := hex.DecodeString(txHex)
	fundedTx, _ := btcutil.NewTxFromBytes(rawTxBytes)

	// Map vouts by decoding PkScript from raw transaction
	for i, out := range fundedTx.MsgTx().TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(out.PkScript, netParams)
		if err != nil || len(addrs) == 0 {
			continue
		}
		addr := addrs[0].EncodeAddress()
		if path, exists := addrToPathMap[addr]; exists {
			inputs = append(inputs, map[string]any{"txid": txid, "vout": i})
			receivePaths = append(receivePaths, path)
			recvPubs = append(recvPubs, addrToPubMap[addr])
		}
	}

	// 4. DERIVE CHANGE ADDRESS
	changeIdx := uint32(rand.Intn(100000))
	changePath := []uint32{84 + hdkeychain.HardenedKeyStart, 1 + hdkeychain.HardenedKeyStart, accountIdx + hdkeychain.HardenedKeyStart, 1, changeIdx}

	changeKey, _ := derivePath(masterKey, changePath)
	changePub, _ := changeKey.ECPubKey()
	changeKey.Zero()
	changeAddr, _ := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(changePub.SerializeCompressed()), netParams)

	var outputs []map[string]float64
	totalOut := 0.0

	minerFee := 0.0001
	if attackScenario == 4 { // Fee Sniping
		minerFee = 0.05 // High fee, but leaves enough for outputs to be created without createpsbt throwing an error
	}

	for range numOutputs {
		sendAmount, _ := strconv.ParseFloat(fmt.Sprintf("%.8f", 0.001+(float64(rand.Intn(5))/100.0)), 64)
		if totalOut+sendAmount+minerFee >= totalIn {
			break // Prevent creating invalid transactions where outputs > inputs
		}
		var recipient string
		addrRes, _ := rpc.Call("getnewaddress", []any{})
		json.Unmarshal(addrRes, &recipient)
		outputs = append(outputs, map[string]float64{recipient: sendAmount})
		totalOut += sendAmount
	}

	changeAmount, _ := strconv.ParseFloat(fmt.Sprintf("%.8f", totalIn-totalOut-minerFee), 64)
	if changeAmount > 0 {
		outputs = append(outputs, map[string]float64{changeAddr.EncodeAddress(): changeAmount})
	}

	// 5. CREATE PSBT
	var psbtB64 string
	psbtRes, err := rpc.Call("createpsbt", []any{inputs, outputs, 0, false})
	if err != nil {
		return attackScenario, fmt.Errorf("createpsbt failed: %v", err)
	}
	json.Unmarshal(psbtRes, &psbtB64)

	updatedPsbtRes, err := rpc.Call("utxoupdatepsbt", []any{psbtB64})
	if err == nil {
		json.Unmarshal(updatedPsbtRes, &psbtB64)
	}

	// Manipulate the PSBT byte structures based on attacks
	packet, _ := psbt.NewFromRawBytes(bytes.NewReader(decodeBase64(psbtB64)), false)

	for i := range packet.Inputs {
		// Populate NonWitnessUtxo directly from in-memory fundedTx when available, avoiding redundant RPC
		inHash := packet.UnsignedTx.TxIn[i].PreviousOutPoint.Hash
		if fundedTx != nil && inHash == fundedTx.MsgTx().TxHash() {
			packet.Inputs[i].NonWitnessUtxo = fundedTx.MsgTx()
		} else {
			txid := inHash.String()
			rawTxHexRes, err := rpc.Call("gettransaction", []any{txid})
			if err == nil {
				var txData map[string]any
				json.Unmarshal(rawTxHexRes, &txData)
				if hexStr, ok := txData["hex"].(string); ok {
					rawTxBytes, _ := hex.DecodeString(hexStr)
					nonWitnessUtxo, _ := btcutil.NewTxFromBytes(rawTxBytes)
					packet.Inputs[i].NonWitnessUtxo = nonWitnessUtxo.MsgTx()
				}
			}
		}

		packet.Inputs[i].Bip32Derivation = []*psbt.Bip32Derivation{{
			PubKey:               recvPubs[i],
			MasterKeyFingerprint: binaryToUint32(fingerprint),
			Bip32Path:            receivePaths[i],
		}}

		if attackScenario == 1 || attackScenario == 7 { // Sighash Attack
			packet.Inputs[i].SighashType = 0x02 // SIGHASH_NONE
		}
		if attackScenario == 3 { // Ownership Hijacking
			packet.Inputs[i].Bip32Derivation[0].MasterKeyFingerprint = 0xDEADBEEF // Wrong fingerprint
		}
		if attackScenario == 6 { // Network Mismatch (Mainnet path on Testnet)
			packet.Inputs[i].Bip32Derivation[0].Bip32Path[1] = 0 + hdkeychain.HardenedKeyStart // 0' is Mainnet coin type
		}
		if attackScenario == 8 { // Fake WitnessUtxo Amount Attack
			packet.Inputs[i].WitnessUtxo.Value = packet.Inputs[i].WitnessUtxo.Value / 10 // Lie about the input amount to steal fee
		}
		if attackScenario == 9 { // RBF Hijacking Attack
			packet.UnsignedTx.TxIn[i].Sequence = 0xfffffffd // Enable RBF without user knowing
		}
	}

	if attackScenario == 10 { // Dust Spam Attack
		for range 50 {
			packet.UnsignedTx.AddTxOut(&wire.TxOut{
				Value:    500, // Dust
				PkScript: []byte{0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			})
			packet.Outputs = append(packet.Outputs, psbt.POutput{})
		}
	}

	if attackScenario == 12 { // OOM DoS Bomb Attack
		// Duplicate the first input and output 5000 times to stress test memory
		for range 5000 {
			packet.UnsignedTx.AddTxIn(packet.UnsignedTx.TxIn[0])
			packet.Inputs = append(packet.Inputs, packet.Inputs[0])
			packet.UnsignedTx.AddTxOut(packet.UnsignedTx.TxOut[0])
			packet.Outputs = append(packet.Outputs, packet.Outputs[0])
		}
	}

	if attackScenario == 13 { // Malformed Parser Bomb (Nil/OOB)
		// Inject a properly formatted but semantically empty Bip32Derivation
		dummyPubKey := make([]byte, 33)
		dummyPubKey[0] = 0x02
		packet.Inputs[0].Bip32Derivation = append(packet.Inputs[0].Bip32Derivation, &psbt.Bip32Derivation{
			PubKey:    dummyPubKey,
			Bip32Path: []uint32{},
		})
	}

	if attackScenario == 14 { // LockTime Hostage Attack
		packet.UnsignedTx.LockTime = 10000000 // Block height far in the future
	}

	if attackScenario == 16 { // Integer Overflow Fee Attack
		// Set WitnessUtxo.Value to MAX_INT64 to cause potential integer overflow during fee calculation
		packet.Inputs[0].WitnessUtxo.Value = math.MaxInt64
		if packet.Inputs[0].NonWitnessUtxo != nil && len(packet.Inputs[0].NonWitnessUtxo.TxOut) > 0 {
			packet.Inputs[0].NonWitnessUtxo.TxOut[0].Value = math.MaxInt64
		}
	}

	if changeAmount > 0 {
		for i := range packet.Outputs {
			// Find the output that matches our change amount (using math.Round to avoid float precision truncation)
			if packet.UnsignedTx.TxOut[i].Value == int64(math.Round(changeAmount*100000000)) {
				packet.Outputs[i].Bip32Derivation = []*psbt.Bip32Derivation{{
					PubKey:               changePub.SerializeCompressed(),
					MasterKeyFingerprint: binaryToUint32(fingerprint),
					Bip32Path:            changePath,
				}}

				if attackScenario == 2 || attackScenario == 7 { // Fake Change Attack
					// Mismatch the public key in Bip32!
					hackerKey, _ := btcec.NewPrivateKey()
					packet.Outputs[i].Bip32Derivation[0].PubKey = hackerKey.PubKey().SerializeCompressed()
				}

				if attackScenario == 11 { // Change Omission Attack
					packet.Outputs[i].Bip32Derivation = nil
				}
				break
			}
		}
	}

	var b bytes.Buffer
	packet.Serialize(&b)
	psbtB64 = base64.StdEncoding.EncodeToString(b.Bytes())

	// 6. SELA VAULT SIGNING
	txDetails, err := extractTxDetails(packet, true, accountIdx, true)
	if err == nil {
		_, err = signTransactionInputs(packet, masterKey, netParams, true, accountIdx, txDetails)
	}

	attackName := ""
	switch attackScenario {
	case 0:
		attackName = "Valid Transaction"
	case 1:
		attackName = "Sighash Attack"
	case 2:
		attackName = "Fake Change Attack"
	case 3:
		attackName = "Ownership Hijacking"
	case 4:
		attackName = "Fee Sniping (Dust Output)"
	case 5:
		attackName = "BIP Mismatch Attack"
	case 6:
		attackName = "Network Mismatch Attack"
	case 7:
		attackName = "Combined Attack (Sighash+Change)"
	case 8:
		attackName = "Fake WitnessUtxo Amount Attack"
	case 9:
		attackName = "RBF Hijacking Attack"
	case 10:
		attackName = "Dust Spam Attack"
	case 11:
		attackName = "Change Omission Attack"
	case 12:
		attackName = "OOM DoS Bomb Attack"
	}

	dumpData := fmt.Sprintf(`
        --- REPRODUCTION DATA ---
        Mnemonic:       %s
        Passphrase:     %s
        Account Index:  %d
        Attack Type:    %s
        Num Inputs:     %d (Total: %.8f BTC)
        Num Outputs:    %d (Total: %.8f BTC)
        Miner Fee:      %.8f BTC
        Raw PSBT (B64):
        %s
        -------------------------`, mnemonic, passphrase, accountIdx, attackName, numInputs, totalIn, numOutputs, totalOut, totalIn-totalOut-changeAmount, psbtB64)

	if attackScenario == 15 { // Deterministic Signature Anti-Klepto Test
		if err != nil {
			return attackScenario, fmt.Errorf("Deterministic Signature Anti-Klepto Test failed to sign: %v\n%s", err, dumpData)
		}
		// Sign again
		txDetails2, err2 := extractTxDetails(packet, true, accountIdx, true)
		if err2 != nil {
			return attackScenario, fmt.Errorf("Deterministic Signature Test failed to extract TxDetails: %v\n%s", err2, dumpData)
		}
		_, err2 = signTransactionInputs(packet, masterKey, netParams, true, accountIdx, txDetails2)
		if err2 != nil {
			return attackScenario, fmt.Errorf("Deterministic Signature Test failed on second sign: %v\n%s", err2, dumpData)
		}
		sig1 := packet.Inputs[0].PartialSigs[0].Signature
		sig2 := packet.Inputs[0].PartialSigs[1].Signature
		if !bytes.Equal(sig1, sig2) {
			return attackScenario, fmt.Errorf("🚨 CRITICAL: Malicious transaction bypassed Sela Vault! Non-Deterministic Signature Detected (Vulnerable to Dark Skippy / Nonce Exfiltration)!\n%s", dumpData)
		}
		return attackScenario, nil
	}

	if attackScenario == 0 || attackScenario == 9 || attackScenario == 11 { // Valid Tx, RBF Tx, or Change Omission
		if err != nil {
			return attackScenario, fmt.Errorf("Valid TX / Change Omission should have passed Sela Vault without error: %v\n%s", err, dumpData)
		}
	} else {
		if err == nil {
			return attackScenario, fmt.Errorf("🚨 CRITICAL: Malicious transaction bypassed Sela Vault!\n%s", dumpData)
		}
	}

	return attackScenario, nil
}

func decodeBase64(s string) []byte {
	dec, _ := base64.StdEncoding.DecodeString(s)
	return dec
}

func binaryToUint32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
