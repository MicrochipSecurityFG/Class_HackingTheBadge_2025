import requests
from bitcoinlib.wallets import Wallet, WalletError, wallets_list
from bitcoinlib.transactions import Transaction, Input, Output
from bitcoinlib.encoding import to_bytes
from bitcoinlib.keys import Key
from bitcoinlib.keys import HDKey
from bitcoinlib.services.services import Service
from bitcoinlib.mnemonic import Mnemonic
import pyperclip
from colorama import init, Fore, Style
import qrcode
import readchar
import uuid

# ANSI color codes
GREEN = '\033[92m'
RED = '\033[91m'
RESET = '\033[0m'

NETWORK = "testnet"
INSTRUCTOR_ADDRESS = "tb1q7hk2whadhsm63zskphe3usqwmr3g3jvhl0lkme"  # Fixed address for sweeping funds

class PublicWallet:
    def __init__(self, wallet_name=None):
        self.wallet_name = wallet_name

    def import_wallet(self, key_input):
        """
        Imports a wallet using either seed words (mnemonic) or an extended public key (xpub).
        If seed words are given, creates a full wallet.
        If xpub is given, creates a watch-only wallet.
        """
        try:
            if key_input.strip().lower().startswith('xpub') or key_input.strip().lower().startswith('tpub'):
                # Watch-only wallet from xpub
                wallet = Wallet.create(self.wallet_name, keys=key_input, network=NETWORK, witness_type='segwit', watchonly=True)
            else:
                # Assume mnemonic phrase
                wallet = Wallet.create(self.wallet_name, keys=key_input, network=NETWORK, witness_type='segwit')
            
            wallet.scan()  # Scan blockchain for UTXOs
            print("\nGetting wallet info (~10secs)....")
            return wallet.info()
        except WalletError as e:
            return f"Error importing wallet: {e}"

    def check_balance(self):
        """Fetches and displays the balance of the wallet in tBTC."""
        try:
            wallet = Wallet(self.wallet_name)
            wallet.scan(rescan_used=True)
            total_balance_satoshis = wallet.balance()
            total_balance_btc = total_balance_satoshis / 100_000_000  # Convert to tBTC
            return f"{total_balance_btc:.8f} tBTC ({total_balance_satoshis} sats)"
        except WalletError as e:
            return f"Error checking balance: {e}"

    def has_root_private_key(self):
        try:
            wallet = Wallet(self.wallet_name)
            all_wallet_keys = wallet.keys()
            private = wallet.keys(is_private=True, depth=0)
            if not private:
                return False
            else:
                return True
        except WalletError as e:
            return False
        except Exception as e:
            print(f"[DEBUG] Unexpected exception: {e}")
            return False

    def create_transaction(self, recipient, amount_sats):
        """Creates a raw unsigned P2WPKH transaction for export, 2 sat/vB fee, locktime 0, with random key signed reference."""
        wallet = Wallet(self.wallet_name)
        wallet.scan()  # Ensure UTXOs are up-to-date

        # Check available UTXOs
        utxos = wallet.utxos()
        if not utxos:
            return "Error: No UTXOs available"
        
        # Find a single UTXO that can cover the amount plus estimated fee
        selected_utxo = None
        estimated_fee = 500 # using fixed fees
        total_required = amount_sats + estimated_fee

        for utxo in utxos:
            if utxo['value'] >= total_required:
                selected_utxo = utxo
                break
        
        if not selected_utxo:
            total_available = sum(utxo['value'] for utxo in utxos)
            return f"Error: No single UTXO found with sufficient funds for {total_required} sats (Requested: {amount_sats} sats)"

        # Use selected UTXO
        change_address = selected_utxo['address']

        # Create transaction
        t = Transaction(network='testnet', locktime=0, witness_type='segwit')
        t.add_input(
            prev_txid=selected_utxo['txid'],
            output_n=selected_utxo['output_n'],
            value=selected_utxo['value'],
            address=selected_utxo['address'],
            witness_type='segwit'
        )
        t.add_output(amount_sats, recipient)

        #fixed fee
        fee = 500
        change_amount = selected_utxo['value'] - amount_sats - fee

        # Adjust outputs
        if change_amount >= 0:
            t.outputs = []
            t.add_output(amount_sats, recipient)
            if change_amount > 0:
                t.add_output(change_amount, change_address)
        else:
            return "Error: Insufficient funds for fee"

        # Validate funds
        total_required = amount_sats + fee
        if total_required > selected_utxo['value']:
            return f"Error: {total_required} sats (amount + fee) exceeds selected UTXO {selected_utxo['value']} sats"

        # Extract pubkey hash (for P2WPKH, it's in the script or derivable from address)
        pubkey_hash = selected_utxo['script'][2:]  # P2WPKH script is 0014<hash160>, skip first 4 chars (0014)
        pubkey_hash = pubkey_hash.hex()
        
        # Get the key and its derivation path using key_id
        key_id = selected_utxo.get('key_id')
        if key_id is not None:
            key = wallet.key(key_id)
            derivation_path = key.path if key else "Unknown (key not found for key_id)"
        else:
            derivation_path = "Unknown (key_id not present in UTXO)"
        
        # Calculate precise fee based on transaction size
        vsize = t.estimate_size()
        print(t)
        print(key)
        # Display details
        print("\nTransaction Details:")
        print(f"Input: {selected_utxo['txid']}")
        print(f"Input point: {selected_utxo['value']}:{selected_utxo['output_n']}")
        print(f"ScriptPubKey Path: {derivation_path}")
        
        print(f"Output 1: {recipient} - {amount_sats} sats")
        if change_amount > 0:
            print(f"Output 2 (Change): {change_address} - {change_amount} sats")
        print(f"Fee: {fee} sats ({fee / vsize:.1f} sat/vB, {vsize} vbytes)")
        print(f"Total spent: {total_required} sats")

        # Determine if private key is available            
        if self.has_root_private_key():
            print("[DEBUG] has_root_private_key returned True")
            # Ask for confirmation before signing and broadcasting
            confirm = input("\nbroadcast this transaction? (y/n): ").strip().lower()
            if confirm == 'y':
                # Get the key used in the input UTXO
                t.sign(keys=key.key())
                rawtx = t.raw().hex()
                tx = Transaction.parse_hex(rawtx, network=NETWORK)
                service = Service(network=NETWORK)
                service.sendrawtransaction(rawtx)
                print(f"\n✅ Transaction signed and broadcast!\nTXID: {tx.txid}")
                print(rawtx)
                return
        else:
           # Generate unsigned transaction for export               
           unsigned_tx_bytes = t.raw()
           unsigned_tx_hex = unsigned_tx_bytes.hex()

           # Split the path and extract the last two components
           path_parts = derivation_path.split("/")
           last_two = path_parts[-2:]  # ['1', '3']
           last_two_str = f"{last_two[0]}:{last_two[1]}"

           # Combine final string
           clipboard_text = f"{last_two_str}:{selected_utxo['value']}:{selected_utxo['output_n']}:{unsigned_tx_hex}"

           # Output and copy to clipboard
           print(f"\nCopy this: {clipboard_text}\n")
           pyperclip.copy(clipboard_text)
           print("✅ Copied to clipboard!")
           
           return

    def sweep_funds(self):
        """Sweeps all funds from the wallet to the Instructor address or a user-specified custom address with a dynamic fee of 4 sats/vbyte."""
        try:
            # Prompt user to choose between Instructor address or custom address
            print("\nChoose the destination address for the sweep:")
            print(f"1. Instructor Address ({INSTRUCTOR_ADDRESS})")
            print("2. Custom Address")
            choice = readchar.readkey()
    
            if choice == '1':
                target_address = INSTRUCTOR_ADDRESS
            elif choice == '2':
                target_address = input("\nEnter the custom address: ").strip()
                # Basic validation for non-empty address
                if not target_address:
                    return "Error: Custom address cannot be empty"
            else:
                return "Error: Invalid choice. Please press 1 or 2."
    
            wallet = Wallet(self.wallet_name)
            wallet.scan()  # Ensure UTXOs are up-to-date
    
            # Check available UTXOs
            utxos = wallet.utxos()
            if not utxos:
                return "Error: No UTXOs available to sweep"
    
            # Create transaction to sweep all UTXOs
            t = Transaction(network='testnet', locktime=0, witness_type='segwit')
            total_input_value = 0
    
            # Add all UTXOs as inputs
            for utxo in utxos:
                t.add_input(
                    prev_txid=utxo['txid'],
                    output_n=utxo['output_n'],
                    value=utxo['value'],
                    address=utxo['address'],
                    witness_type='segwit'
                )
                total_input_value += utxo['value']
    
            # Estimate transaction size and calculate dynamic fee
            vsize = t.estimate_size()
            fee_rate = 4  # 4 sats per vbyte
            fee = vsize * fee_rate
            sweep_amount = total_input_value - fee
    
            if sweep_amount <= 0:
                return "Error: Insufficient funds to cover fee"
    
            # Add output to target address
            t.add_output(sweep_amount, target_address)
    
            # Display transaction details
            print("\nSweep Transaction Details:")
            print(f"Inputs: {len(utxos)} UTXOs")
            print(f"Total Input Value: {total_input_value} sats")
            print(f"Output: {target_address} - {sweep_amount} sats")
            print(f"Fee: {fee} sats ({fee_rate} sat/vB, {vsize} vbytes)")
    
            # Sign the transaction
            for utxo in utxos:
                key_id = utxo.get('key_id')
                if key_id is not None:
                    key = wallet.key(key_id)
                    t.sign(keys=key.key())
                else:
                    return "Error: Key ID not found for UTXO"
    
            # Ask for confirmation before broadcasting
            confirm = input("\nBroadcast this sweep transaction? (y/n): ").strip().lower()
            if confirm == 'y':
                rawtx = t.raw().hex()
                tx = Transaction.parse_hex(rawtx, network=NETWORK)
                service = Service(network=NETWORK)
                service.sendrawtransaction(rawtx)
                print(f"\n✅ Sweep transaction signed and broadcast!\nTXID: {tx.txid}")
                print(rawtx)
                return
            else:
                print("Sweep transaction aborted by user.")
                return
    
        except Exception as e:
            return f"Error sweeping funds: {e}"

    def verify_and_send_raw_tx(self):
        try:
            # Initialize service for blockchain lookups
            service = Service(network=NETWORK)

            # Prompt user for raw transaction hex
            raw_tx_hex = input("Please paste your raw signed transaction (in hex): ").strip()
            if not raw_tx_hex:
                print("No transaction hex provided.")
                return False

            # Parse the raw transaction
            tx = Transaction.parse_hex(raw_tx_hex, network=NETWORK)
            
            # Fetch and set input values from blockchain
            for i, tx_input in enumerate(tx.inputs):
                try:
                    # Convert prev_txid to hex string if it's in bytes
                    prev_txid = tx_input.prev_txid.hex() if isinstance(tx_input.prev_txid, bytes) else tx_input.prev_txid
                    print(f"Fetching previous tx: {prev_txid}")
                    
                    # Get the previous transaction
                    prev_tx = service.gettransaction(prev_txid)
                    if not prev_tx:
                        print(f"Failed to fetch transaction {prev_txid}")
                        return False

                    print(f"Previous tx outputs found: {len(prev_tx.outputs)}")
                    
                    # Convert output_n from bytes to integer 
                    output_n = int.from_bytes(tx_input.output_n, byteorder='big')           
                    print(f"Looking for output #{output_n}")

                    if len(prev_tx.outputs) > output_n:
                        tx_input.value = prev_tx.outputs[output_n].value
                        print(f"Set input {i} value to {tx_input.value} satoshis from blockchain")
                        # Verify the value is set
                        print(f"Confirmed input {i} value: {tx.inputs[i].value} satoshis")
                    else:
                        print(f"Output {output_n} not found in previous tx {prev_txid}")
                        return False
                except Exception as e:
                    print(f"Error fetching UTXO for input {i}: {str(e)}")
                    print(f"Prev txid type: {type(tx_input.prev_txid)}")
                    print(f"Output_n type: {type(tx_input.output_n)}")
                    print("Please ensure you're connected to the internet and using the correct network")
                    return False

            # Force update of transaction totals
            tx.update_totals()
            print(f"After update_totals - Input total: {tx.input_total} satoshis")

            # Verify all signatures
            try:
                if tx.verify():
                    print(f"{Fore.GREEN}All input signatures are valid.{Style.RESET_ALL}")
                    print(f"Transaction fee: {tx.fee} satoshis")
                else:
                    print(f"{Fore.RED}Signature verification failed.{Style.RESET_ALL}")
                    return False
            except VerificationError as e:
                print(f"{Fore.RED}Signature verification failed: {e}{Style.RESET_ALL}")
                return False
            except Exception as e:
                print(f"{Fore.RED}Verification failed with error: {e}{Style.RESET_ALL}")
                return False

            # Show transaction details
            print(f"\nTransaction Details:")
            print(f"TxID: {tx.txid}")
            print(f"Inputs: {len(tx.inputs)}")
            print(f"Outputs: {len(tx.outputs)}")
            print(f"Total input value: {tx.input_total} satoshis")
            print(f"Total output value: {tx.output_total} satoshis")

            # Ask user if they want to broadcast
            confirm = input("\nDo you want to send this transaction to the network? (yes/no): ").strip().lower()
            if confirm != 'yes':
                print("Transaction not sent. Aborted by user.")
                return False

            # Broadcast transaction
            txid = service.sendrawtransaction(raw_tx_hex)

            if txid:
                print(f"\nTransaction successfully sent! Transaction ID: {txid}")
                return txid
            else:
                print("Failed to send transaction. Check network or raw hex.")
                return False

        except ValueError as e:
            print(f"Error parsing transaction: {e}")
            return False
        except Exception as e:
            print(f"An error occurred: {e}")
            return False
            
    def wallet_info(self):
        """
        Displays detailed wallet information using wallet.info().
        """
        
        wallet = Wallet(self.wallet_name)
        #wallet.scan()  # Ensure it's up to date
   
        # Print full wallet details
        print(wallet.info(detail=5)) 

    def open_wallet(self):
        """Opens an existing wallet by selecting from a numbered list."""
        wallets = self.list_wallets()
        
        if not wallets:
            print("No wallets available.")
            return None
        print("\nSelect a wallet:")
        for i, wallet_name in enumerate(wallets, 1):
            print(f"{i}. {wallet_name}")
        try:
            choice = int(input("Enter the number of the wallet: ")) - 1
            if 0 <= choice < len(wallets):
                self.wallet_name = wallets[choice]             
                wallet = Wallet(self.wallet_name)
                service = Service(network='testnet', providers=['blockstream'])  # Try 'blockcypher', 'bitcoind', etc.
                wallet.service = service  # Assign the service to the wallet       
                return self.wallet_name
            else:
                print("Invalid selection.")
        except ValueError:
            print("Invalid input, please enter a number.")
        return None

    def create_new_wallet(self):
            """
            Creates a new Bitcoin testnet wallet with a user-specified name and a 12-word mnemonic seed phrase.
            Prevents overwriting an existing wallet and ensures each wallet has its own seed phrase file.
            """
            mnemonic_obj = Mnemonic()
            mnemonic = mnemonic_obj.generate()
            
            # Prompt user for wallet name
            while True:
                wallet_name = input("Enter a name for your new wallet: ").strip()
                if not wallet_name:  # Check if input is empty
                    print("Error: Wallet name cannot be empty. Please try again.")
                elif wallet_name in self.list_wallets():  # Check if name already exists
                    print(f"Error: Wallet '{wallet_name}' already exists. Please choose a different name.")
                else:
                    break

            try:
                wallet = Wallet.create(wallet_name, keys=mnemonic, network=NETWORK)
                print(f"\n✅ New Wallet Created: {wallet_name}")
                print(f"🔑 Mnemonic Seed Phrase: {mnemonic}")
                print("⚠️ Keep these words safe! They can recover your wallet.")

                # Save mnemonic securely in a local file
                mnemonic_file = f"{wallet_name}_mnemonic.txt"
                with open(mnemonic_file, "w") as f:
                    f.write(mnemonic)
                
                print(f"📁 Seed words saved to {mnemonic_file} (DO NOT SHARE!)")
                
                # Set this as the current wallet
                self.wallet_name = wallet_name
                return wallet_name  # Return the name instead of the wallet object for consistency

            except WalletError as e:
                print(f"❌ Error creating wallet: {e}")
                return None

    def display_addresses(self, count=5):
        """Displays the first 'count' addresses of the wallet with QR codes, including extended private keys."""
        if not self.wallet_name:
            print("No wallet selected.")
            return
        try:
            wallet = Wallet(self.wallet_name)
            keys = wallet.keys(depth=5)[:count]
            print("\nWallet Addresses:")
            qr = qrcode.QRCode(
                version=1,  # Smallest size, matches reference
                error_correction=qrcode.constants.ERROR_CORRECT_L,  # Low error correction, matches reference
                box_size=10,  # Size from reference
                border=6,     # Increased border for ASCII (was 4 in PNG)
            )
            #if wallet.watchonly:
            #    print("🔒 This is a watch-only wallet. Private keys will not be shown.\n")
            
            for i, key in enumerate(keys):
                private_key_hex = key.private.hex() if key.private else "N/A (watch-only)"
                public_key_hex = key.public.hex() if key.public else "N/A"
            
                print(f"{i + 1}. Address: {key.address}")
                print(f"   Private Key:      {private_key_hex}")
                print(f"   Public Key:       {public_key_hex}")
                print(f"   Path:             {key.path}")

                # Generate QR code with Bitcoin URI format
                qr_data = f"bitcoin:{key.address}"
                qr.clear()
                qr.add_data(qr_data)
                qr.make(fit=True)
                # Print ASCII QR code with inverted colors and border
                qr.print_ascii(invert=True)  # White squares on black background
                print()  # Extra line for readability
        except WalletError:
            print("Unable to retrieve wallet addresses.")
        except Exception as e:
            print(f"Error displaying addresses: {e}")

        return None

    def list_wallets(self):
        """Lists all existing wallets by name."""
        return [w["name"] for w in wallets_list()]

if __name__ == "__main__":
    pc = PublicWallet()
    while True:
        print("\nPublic Wallet Menu:")
        
        if pc.wallet_name:
            print(f"Currently Open Wallet: {pc.wallet_name}")
            print("1. Check Balance")
            print("2. Create Transaction")
            print("3. Wallet Info")
            print("4. Verify and Send Raw")
            print("5. Display Address QRs")
            if pc.has_root_private_key():
                print("6. Send All Funds")
                print("7. Exit")
            else:
                print("6. Exit")

            choice = readchar.readkey()

            if choice == "1":
                print("Looking up balance....")
                print("Balance:", pc.check_balance())

            elif choice == "2":
                recipient = input("Enter recipient address: ")
                amount_sats = int(input("Enter amount in satoshis: "))
                pc.create_transaction(recipient, amount_sats)

            elif choice == "3":
                pc.wallet_info()

            elif choice == "4":
                pc.verify_and_send_raw_tx()

            elif choice == "5":
                pc.display_addresses(1)

            elif choice == "6" and pc.has_root_private_key():
                print("Sweeping all funds to fixed address...")
                result = pc.sweep_funds()
                print(result)

            elif (choice == "6" and not pc.has_root_private_key()) or (choice == "7" and pc.has_root_private_key()):
                print("Goodbye!")
                break

            else:
                print("Invalid selection, please try again.")

        else:
            print("1. Import Wallet")
            print("2. Open Existing Wallet")
            print("3. Exit")
            
            choice = readchar.readkey()

            if choice == "1":
                name = input("Enter wallet name: ")
                xpub = input("Enter XPUB or seed words: ")
                pw = PublicWallet(name)
                result = pw.import_wallet(xpub)
                print("Wallet Info:", result)
                pc = pw  # Set newly imported wallet as current

            elif choice == "2":
                selected_wallet_name = pc.open_wallet()
                if selected_wallet_name:
                    print(f"Selected wallet: {selected_wallet_name}")

            elif choice == "3":
                print("Goodbye!")
                break

            else:
                print("Invalid selection, please try again.")