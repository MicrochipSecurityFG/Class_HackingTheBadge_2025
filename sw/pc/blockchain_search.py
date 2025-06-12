import sys
import time
from bitcoinlib.services.services import Service

# --- CONFIG ---
OUTPUT_FILE = "p2wpkh_hashes.txt"
NETWORK = 'testnet'

# --- INIT SERVICE ---
service = Service(network=NETWORK, provider_name='mempool.testnet')
results = []

# --- Parse Command-Line Args ---
args = sys.argv[1:]

def get_block_range_from_args():
    if len(args) >= 1:
        try:
            start = int(args[0])
        except ValueError:
            print("Invalid start block.")
            exit(1)
    else:
        start = int(input("Start block height: ").strip())

    if len(args) >= 2:
        if args[1] == "":
            end = service.blockcount()
        else:
            try:
                end = int(args[1])
            except ValueError:
                print("Invalid end block.")
                exit(1)
    else:
        end_input = input("End block height (leave blank for latest): ").strip()
        if end_input == "":
            end = service.blockcount()
            print(f"Using latest block height: {end}")
        else:
            end = int(end_input)

    if end < start:
        print("End block must be greater than or equal to start block.")
        exit(1)

    return start, end

start_block, end_block = get_block_range_from_args()
estimated_blocks = end_block - start_block + 1
print(f"\nScanning from block {start_block} to {end_block} ({estimated_blocks} blocks)")

if not args:
    confirm = input("Proceed? (y/n): ").strip().lower()
    if confirm != 'y':
        print("Aborted.")
        exit()

# --- Scanning Logic ---
pattern_hex = '0014'  # P2WPKH witness version (00) + 20-byte push (14)
pattern_bytes = bytes.fromhex(pattern_hex)

for block_height in range(start_block, end_block + 1):
    print(f"Scanning block {block_height}...")

    try:
        raw_block = service.getrawblock(block_height)
        raw_bytes = bytes.fromhex(raw_block)
    except Exception as e:
        print(f"    Failed to retrieve raw block {block_height}: {e}")
        time.sleep(1)
        continue

    i = 0
    while i < len(raw_bytes) - 24:  # 4 bytes of pattern + 20 bytes of pubkey hash
        if raw_bytes[i:i+2] == b'\x00\x14':
            pubkey_hash = raw_bytes[i+2:i+22]
            results.append(pubkey_hash.hex())
            i += 22
        else:
            i += 1

print(f"Found {len(results)} P2WPKH pubkey hashes")

# --- Output Results ---
with open(OUTPUT_FILE, 'w') as f:
    for pubkey_hash in results:
        f.write(f"{pubkey_hash}\n")

print(f"Saved pubkey hashes to {OUTPUT_FILE}")
