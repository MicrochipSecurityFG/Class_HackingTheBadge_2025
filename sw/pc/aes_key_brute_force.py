import hashlib
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import serial
import serial.tools.list_ports
import time

def read_bip39_wordlist(file_path):
    try:
        with open(file_path, 'r') as f:
            return [word.strip() for word in f.readlines() if word.strip()]
    except FileNotFoundError:
        print(f"Error: BIP39 wordlist file '{file_path}' not found")
        exit(1)

def get_serial_port():
    ports = serial.tools.list_ports.comports()
    if not ports:
        print("Error: No serial ports found")
        exit(1)
    print("Available serial ports:")
    for port in ports:
        print(f"- {port.device}: {port.description}")
    selected_port = ports[0].device
    print(f"Selecting first port: {selected_port}")
    return selected_port

def get_ciphertext_from_serial(port, baudrate=115200, incorrect_pin="123"):
    try:
        with serial.Serial(port, baudrate, timeout=1) as ser:
            time.sleep(1)
            ser.flushInput()
            ser.write(b'3\n')
            time.sleep(0.5)
            ser.write(f"{incorrect_pin}\n".encode())
            response = []
            start_time = time.time()
            while time.time() - start_time < 5:
                line = ser.readline().decode('ascii', errors='ignore').strip()
                if line:
                    response.append(line)
                    if len(line) > 100 and all(c in '0123456789abcdef' for c in line.lower()):
                        cipher_text = bytes.fromhex(line)
                        print(f"Received ciphertext ({len(cipher_text)} bytes):")
                        print(cipher_text.hex())
                        print("Full serial response:")
                        for r in response:
                            print(f"> {r}")
                        return cipher_text
            print("Error: Could not retrieve ciphertext from serial")
            print("Full serial response:")
            for r in response:
                print(f"> {r}")
            exit(1)
    except serial.SerialException as e:
        print(f"Serial error: {e}")
        exit(1)

def compute_key(pin_bytes, timer_bytes):
    """Compute AES key from PIN and timestamp bytes."""
    data = pin_bytes + timer_bytes
    sha256_hash = hashlib.sha256(data).digest()
    return sha256_hash[:16]

def main():
    parser = argparse.ArgumentParser(description='Decrypt BIP39 ciphertext')
    parser.add_argument('--pin', required=True, help='PIN (ASCII string)')

    args = parser.parse_args()

    try:
        pin_bytes = args.pin.encode('ascii')
        
    except (ValueError, UnicodeEncodeError) as e:
        print(f"Error: {e}")
        exit(1)

    if len(pin_bytes) < 1:
        print("Error: PIN cannot be empty")
        exit(1)
    print(f"PIN length: {len(pin_bytes)} bytes")
    print(f"PIN bytes: {pin_bytes.hex().upper()}")

    bip39_wordlist = read_bip39_wordlist('bip39_wordlist.txt')
    serial_port = get_serial_port()
    cipher_text = get_ciphertext_from_serial(serial_port)

    for i in range(0x000000, 0x1000000):
        if i % 0x10000 == 0:
            print(f"Progress: {i:06X}")

        timer_bytes = i.to_bytes(3, byteorder='big')
        key_16_bytes = compute_key(pin_bytes, timer_bytes)

        cipher = AES.new(key_16_bytes, AES.MODE_ECB)
        try:
            decrypted_data = unpad(cipher.decrypt(cipher_text), AES.block_size, style='iso7816')
            decrypted_text = decrypted_data.decode(errors='ignore')
            matched_words = [word for word in bip39_wordlist if word in decrypted_text]
            if len(matched_words) >= 4:
                print(f"[MATCH] Timer: {timer_bytes.hex().upper()} -> Key: {key_16_bytes.hex().upper()}")
                print(f"Full decrypted text:\n{decrypted_text}\n")
                
                break;
            
        except ValueError as e:
            continue

    print("DONE")

if __name__ == "__main__":
    main()