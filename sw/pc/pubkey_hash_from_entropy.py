import itertools
import hashlib
import time
import math
import sys
import multiprocessing as mp
from mnemonic import Mnemonic
from bip32 import BIP32
from bech32 import bech32_encode, convertbits

# --- Bech32 encoding for P2WPKH ---
def pubkey_hash_to_bech32_address(pubkey_hash, hrp="tb"):
    converted = convertbits(pubkey_hash, 8, 5)
    return bech32_encode(hrp, [0] + converted)

# --- Parse derivation path like m/84'/1'/0'/0/0 ---
def parse_path(path):
    indexes = []
    for part in path.split('/'):
        if part == 'm': continue
        hardened = part.endswith("'")
        idx = int(part.rstrip("'"))
        if hardened: idx += 0x80000000
        indexes.append(idx)
    return indexes

# --- Expand 'x' wildcards in hex string ---
def expand_wildcard_hex(template):
    hex_chars = '0123456789abcdef'
    wildcard_positions = [i for i, c in enumerate(template) if c.lower() == 'x']
    for replacements in itertools.product(hex_chars, repeat=len(wildcard_positions)):
        chars = list(template.lower())
        for pos, val in zip(wildcard_positions, replacements):
            chars[pos] = val
        yield ''.join(chars)

# --- Worker function for each process ---
def process_batch(hex_inputs, known_hashes, derivation_indexes, counter, lock):
    mnemo = Mnemonic("english")
    matches = []

    for hex_input in hex_inputs:
        with lock:
            counter.value += 1

        try:
            msg_bytes = bytes.fromhex(hex_input)
        except ValueError:
            continue

        entropy_full = hashlib.sha256(msg_bytes).digest()
        entropy = entropy_full[:16]  # 16 bytes = 12-word mnemonic

        try:
            mnemonic = mnemo.to_mnemonic(entropy)
        except ValueError:
            continue

        seed = Mnemonic.to_seed(mnemonic, passphrase="")
        bip32 = BIP32.from_seed(seed)
        pubkey = bip32.get_pubkey_from_path(derivation_indexes)

        sha256 = hashlib.sha256(pubkey).digest()
        ripemd160 = hashlib.new('ripemd160', sha256).digest()
        pubkey_hash_hex = ripemd160.hex()

        # DEBUG: Print each attempt
        #print(f"[*] Checked: {hex_input} -> {pubkey_hash_hex}")

        if pubkey_hash_hex in known_hashes:
            bech32_addr = pubkey_hash_to_bech32_address(ripemd160)
            matches.append({
                "input": hex_input,
                "entropy": entropy.hex(),
                "mnemonic": mnemonic,
                "pubkey": pubkey.hex(),
                "pubkey_hash": pubkey_hash_hex,
                "bech32": bech32_addr
            })

    return matches

# --- Status update process ---
def status_loop(start_time, counter, total_combinations):
    while counter.value < total_combinations:
        elapsed = time.time() - start_time
        guesses = counter.value
        rate = guesses / elapsed if elapsed > 0 else 0
        remaining = total_combinations - guesses
        eta = remaining / rate if rate > 0 else 0
        eta_min, eta_sec = divmod(int(eta), 60)
        print(f"\r[+] {guesses}/{total_combinations} guesses | {rate:.2f} guesses/sec | ETA: {eta_min}m{eta_sec:02d}s", end='', flush=True)
        time.sleep(1)

# --- Main brute-force logic ---
def parallel_bruteforce(wildcard_input):
    try:
        with open("p2wpkh_hashes.txt", 'r') as f:
            known_hashes = {line.strip() for line in f if line.strip()}
    except FileNotFoundError:
        known_hashes = set()

    wildcard_positions = [i for i, c in enumerate(wildcard_input) if c == 'x']
    total_combinations = 16 ** len(wildcard_positions)

    print(f"[*] Wildcard positions: {wildcard_positions}")
    print(f"[*] Total combinations to test: {total_combinations:,}")

    all_combinations = list(expand_wildcard_hex(wildcard_input))
    if not all_combinations:
        print("[!] No combinations to test. Exiting.")
        return

    num_processes = min(mp.cpu_count(), len(all_combinations))
    batch_size = math.ceil(len(all_combinations) / num_processes)
    batches = [all_combinations[i:i + batch_size] for i in range(0, len(all_combinations), batch_size)]

    manager = mp.Manager()
    counter = manager.Value('i', 0)
    lock = manager.Lock()
    derivation_indexes = parse_path("m/84'/1'/0'/0/0")

    start_time = time.time()
    status_proc = mp.Process(target=status_loop, args=(start_time, counter, total_combinations))
    status_proc.start()
    print("[*] Status monitor started...")

    pool = mp.Pool(processes=num_processes)
    try:
        args = [(batch, known_hashes, derivation_indexes, counter, lock) for batch in batches]
        results = pool.starmap_async(process_batch, args)

        while not results.ready():
            time.sleep(0.2)  # Keep main thread alive and interruptible

        matches = [m for sublist in results.get() for m in sublist]

    except KeyboardInterrupt:
        print("\n[!] KeyboardInterrupt received, terminating workers...")
        pool.terminate()
        pool.join()
        if status_proc.is_alive():
            time.sleep(1)
            status_proc.terminate()
            status_proc.join()
        sys.exit(1)

    else:
        pool.close()
        pool.join()
        if status_proc.is_alive():
            time.sleep(1)
            status_proc.terminate()
            status_proc.join()

    print()  # final newline
    duration = time.time() - start_time
    rate = total_combinations / duration if duration > 0 else 0
    print(f"[+] Done in {duration:.2f}s — {rate:.2f} guesses/sec")

    for match in matches:
        print("\n🚨 MATCH FOUND!\n")
        #print(f"[Original Message Hex]: {match['input']}")
        #print(f"[SHA256 Entropy (16 bytes)]: {match['entropy']}")
        GREEN = "\033[92m"
        RESET = "\033[0m"
        
        print(f"{GREEN}[Mnemonic]: {match['mnemonic']}{RESET}")
        # print(f"{GREEN}[Compressed PubKey]: {match['pubkey']}{RESET}")
        print(f"{GREEN}[PubKey Hash]: {match['pubkey_hash']}{RESET}")
        print(f"{GREEN}[Bech32 Address]: {match['bech32']}{RESET}")

# --- Entry point ---
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python pubkey_hash_from_entropy.py <input_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    try:
        with open(input_file, 'r') as f:
            patterns = [line.strip().lower() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"[!] Input file not found: {input_file}")
        sys.exit(1)

    for i, pattern in enumerate(patterns, 1):
        print(f"\n=== Pattern {i}/{len(patterns)}: {pattern} ===")
        parallel_bruteforce(pattern)

