#!/usr/bin/env python3
"""
Bitcoin Serial Monitor
Connects to a serial port, displays received data, and generates QR codes for Bitcoin addresses.
"""

import serial
import re
import qrcode
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import queue
import sys
from datetime import datetime
import io
from PIL import Image, ImageTk

class BitcoinSerialMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Bitcoin Serial Monitor")
        self.root.geometry("800x600")
        
        # Serial connection variables
        self.serial_conn = None
        self.serial_thread = None
        self.running = False
        self.data_queue = queue.Queue()
        
        # Bitcoin address regex patterns
        self.bitcoin_patterns = [
            # Legacy addresses (P2PKH) - starts with 1
            r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            # P2SH addresses - starts with 3
            r'\b3[a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            # Bech32 addresses (P2WPKH/P2WSH) - starts with bc1
            r'\bbc1[a-z0-9]{39,59}\b',
            # Testnet addresses
            r'\b[2mn][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            r'\btb1[a-z0-9]{39,59}\b'
        ]
        
        self.setup_ui()
        self.process_queue()
        
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Serial port selection
        ttk.Label(main_frame, text="Serial Port:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.port_var = tk.StringVar()
        self.port_combo = ttk.Combobox(main_frame, textvariable=self.port_var, width=15)
        self.port_combo.grid(row=0, column=1, sticky=tk.W, padx=(5, 0), pady=5)
        
        # Refresh ports button
        ttk.Button(main_frame, text="Refresh Ports", 
                  command=self.refresh_ports).grid(row=0, column=2, padx=(5, 0), pady=5)
        
        # Connect/Disconnect button
        self.connect_btn = ttk.Button(main_frame, text="Connect", 
                                     command=self.toggle_connection)
        self.connect_btn.grid(row=0, column=3, padx=(5, 0), pady=5)
        
        # Status label
        self.status_var = tk.StringVar(value="Disconnected")
        ttk.Label(main_frame, textvariable=self.status_var).grid(row=0, column=4, 
                                                                padx=(10, 0), pady=5)
        
        # Data display area
        ttk.Label(main_frame, text="Serial Data:").grid(row=1, column=0, sticky=tk.W, pady=(10, 5))
        
        # Text area for serial data
        self.data_text = scrolledtext.ScrolledText(main_frame, height=15, width=70)
        self.data_text.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), 
                           padx=(0, 10), pady=5)
        
        # QR code display area
        qr_frame = ttk.LabelFrame(main_frame, text="Bitcoin Address QR Code", padding="5")
        qr_frame.grid(row=2, column=3, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.qr_label = ttk.Label(qr_frame, text="No Bitcoin address detected")
        self.qr_label.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure QR frame grid
        qr_frame.columnconfigure(0, weight=1)
        qr_frame.rowconfigure(0, weight=1)
        
        # Bitcoin address display
        ttk.Label(main_frame, text="Detected Address:").grid(row=3, column=0, sticky=tk.W, pady=(10, 5))
        self.address_var = tk.StringVar()
        self.address_entry = ttk.Entry(main_frame, textvariable=self.address_var, 
                                      state="readonly", width=50)
        self.address_entry.grid(row=3, column=1, columnspan=2, sticky=(tk.W, tk.E), 
                               padx=(0, 10), pady=5)
        
        # Copy address button
        ttk.Button(main_frame, text="Copy Address", 
                  command=self.copy_address).grid(row=3, column=3, padx=(5, 0), pady=5)
        
        # Initialize port list
        self.refresh_ports()
        
    def refresh_ports(self):
        """Refresh the list of available serial ports"""
        try:
            import serial.tools.list_ports
            ports = [port.device for port in serial.tools.list_ports.comports()]
            self.port_combo['values'] = ports
            if ports and not self.port_var.get():
                self.port_combo.current(0)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh ports: {e}")
    
    def toggle_connection(self):
        """Toggle serial connection"""
        if self.serial_conn is None:
            self.connect_serial()
        else:
            self.disconnect_serial()
    
    def connect_serial(self):
        """Connect to the selected serial port"""
        port = self.port_var.get()
        if not port:
            messagebox.showerror("Error", "Please select a serial port")
            return
        
        try:
            self.serial_conn = serial.Serial(
                port=port,
                baudrate=115200,
                timeout=1,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                bytesize=serial.EIGHTBITS
            )
            
            self.running = True
            self.serial_thread = threading.Thread(target=self.read_serial_data, daemon=True)
            self.serial_thread.start()
            
            self.connect_btn.config(text="Disconnect")
            self.status_var.set("Connected")
            self.data_text.insert(tk.END, f"Connected to {port} at 115200 baud\n")
            self.data_text.see(tk.END)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to connect to {port}: {e}")
            self.serial_conn = None
    
    def disconnect_serial(self):
        """Disconnect from serial port"""
        self.running = False
        
        if self.serial_conn:
            self.serial_conn.close()
            self.serial_conn = None
        
        if self.serial_thread:
            self.serial_thread.join(timeout=1)
        
        self.connect_btn.config(text="Connect")
        self.status_var.set("Disconnected")
        self.data_text.insert(tk.END, "Disconnected from serial port\n")
        self.data_text.see(tk.END)
    
    def read_serial_data(self):
        """Read data from serial port in a separate thread"""
        while self.running and self.serial_conn:
            try:
                if self.serial_conn.in_waiting > 0:
                    data = self.serial_conn.readline().decode('utf-8', errors='ignore').strip()
                    if data:
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        self.data_queue.put(f"[{timestamp}] {data}")
                else:
                    import time
                    time.sleep(0.01)  # Small delay to prevent excessive CPU usage
            except Exception as e:
                self.data_queue.put(f"Error reading serial data: {e}")
                break
    
    def process_queue(self):
        """Process data from the queue and update UI"""
        try:
            while True:
                data = self.data_queue.get_nowait()
                self.data_text.insert(tk.END, data + "\n")
                self.data_text.see(tk.END)
                
                # Check for Bitcoin addresses
                self.check_for_bitcoin_addresses(data)
                
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.process_queue)
    
    def check_for_bitcoin_addresses(self, text):
        """Check if the text contains any Bitcoin addresses"""
        for pattern in self.bitcoin_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if self.is_valid_bitcoin_address(match):
                    self.display_bitcoin_address(match)
                    break
    
    def is_valid_bitcoin_address(self, address):
        """Basic validation for Bitcoin addresses"""
        # This is a simplified validation
        # In a production app, you'd want more thorough validation
        if len(address) < 26 or len(address) > 62:
            return False
        
        # Check for valid characters based on address type
        if address.startswith(('1', '3')):
            # Legacy addresses
            return all(c in '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' for c in address)
        elif address.startswith(('bc1', 'tb1')):
            # Bech32 addresses
            return all(c in 'qpzry9x8gf2tvdw0s3jn54khce6mua7l' for c in address[3:].lower())
        elif address.startswith(('2', 'm', 'n')):
            # Testnet addresses
            return all(c in '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' for c in address)
        
        return False
    
    def display_bitcoin_address(self, address):
        """Display the Bitcoin address and generate QR code"""
        self.address_var.set(address)
        
        # Generate QR code
        try:
            # Create QR code with Bitcoin URI format
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=6,
                border=4,
            )
            qr.add_data(f"bitcoin:{address}")
            qr.make(fit=True)
            
            # Create QR code image
            qr_image = qr.make_image(fill_color="black", back_color="white")
            
            # Resize image to fit in the label
            qr_image = qr_image.resize((200, 200), Image.Resampling.LANCZOS)
            
            # Convert to PhotoImage for tkinter
            photo = ImageTk.PhotoImage(qr_image)
            
            # Update the label
            self.qr_label.config(image=photo, text="")
            self.qr_label.image = photo  # Keep a reference
            
        except Exception as e:
            self.qr_label.config(text=f"QR Error: {e}")
    
    def copy_address(self):
        """Copy the current Bitcoin address to clipboard"""
        address = self.address_var.get()
        if address:
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(address)
                messagebox.showinfo("Success", "Address copied to clipboard")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to copy address: {e}")
        else:
            messagebox.showwarning("Warning", "No address to copy")
    
    def on_closing(self):
        """Handle application closing"""
        if self.serial_conn:
            self.disconnect_serial()
        self.root.destroy()

def main():
    root = tk.Tk()
    app = BitcoinSerialMonitor(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()
