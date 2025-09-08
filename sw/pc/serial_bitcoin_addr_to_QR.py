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
        
        # Address caching system
        self.cached_addresses = []  # List to store unique addresses
        self.current_address_index = -1  # Index of currently displayed address
        
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
        
        # Navigation controls
        nav_frame = ttk.Frame(main_frame)
        nav_frame.grid(row=4, column=0, columnspan=5, sticky=(tk.W, tk.E), pady=(10, 5))
        
        # Previous button
        self.prev_btn = ttk.Button(nav_frame, text="◀ Previous", 
                                  command=self.previous_address, state="disabled")
        self.prev_btn.grid(row=0, column=0, padx=(0, 5))
        
        # Address counter
        self.address_counter_var = tk.StringVar(value="No addresses")
        ttk.Label(nav_frame, textvariable=self.address_counter_var).grid(row=0, column=1, padx=10)
        
        # Next button
        self.next_btn = ttk.Button(nav_frame, text="Next ▶", 
                                  command=self.next_address, state="disabled")
        self.next_btn.grid(row=0, column=2, padx=(5, 0))
        
        # Clear cache button
        ttk.Button(nav_frame, text="Clear Cache", 
                  command=self.clear_cache).grid(row=0, column=3, padx=(20, 0))
        
        # Address list display
        list_frame = ttk.LabelFrame(main_frame, text="Cached Addresses", padding="5")
        list_frame.grid(row=5, column=0, columnspan=5, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 5))
        
        # Configure grid weights for the list frame
        main_frame.rowconfigure(5, weight=1)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        
        # Listbox with scrollbar for addresses
        list_container = ttk.Frame(list_frame)
        list_container.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        list_container.columnconfigure(0, weight=1)
        list_container.rowconfigure(0, weight=1)
        
        self.address_listbox = tk.Listbox(list_container, height=8)
        self.address_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.address_listbox.bind('<<ListboxSelect>>', self.on_address_select)
        
        # Scrollbar for address list
        list_scrollbar = ttk.Scrollbar(list_container, orient="vertical", command=self.address_listbox.yview)
        list_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.address_listbox.configure(yscrollcommand=list_scrollbar.set)
        
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
        # Add to cache if not already present
        if address not in self.cached_addresses:
            self.cached_addresses.append(address)
            self.update_address_list()
        
        # Set current index to the address
        self.current_address_index = self.cached_addresses.index(address)
        self.update_navigation_buttons()
        self.update_address_counter()
        
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
    
    def copy_address_to_clipboard(self, address):
        """Copy address to clipboard without confirmation dialog"""
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(address)
        except Exception as e:
            # Silently fail for automatic copying
            pass
    
    def update_address_list(self):
        """Update the address listbox with cached addresses"""
        self.address_listbox.delete(0, tk.END)
        for i, address in enumerate(self.cached_addresses):
            # Truncate long addresses for display
            display_address = address[:50] + "..." if len(address) > 50 else address
            self.address_listbox.insert(tk.END, f"{i+1}. {display_address}")
    
    def update_navigation_buttons(self):
        """Update the state of navigation buttons based on current position"""
        if not self.cached_addresses:
            self.prev_btn.config(state="disabled")
            self.next_btn.config(state="disabled")
        else:
            self.prev_btn.config(state="normal" if self.current_address_index > 0 else "disabled")
            self.next_btn.config(state="normal" if self.current_address_index < len(self.cached_addresses) - 1 else "disabled")
    
    def update_address_counter(self):
        """Update the address counter display"""
        if not self.cached_addresses:
            self.address_counter_var.set("No addresses")
        else:
            self.address_counter_var.set(f"Address {self.current_address_index + 1} of {len(self.cached_addresses)}")
    
    def previous_address(self):
        """Navigate to the previous address in the cache"""
        if self.current_address_index > 0:
            self.current_address_index -= 1
            address = self.cached_addresses[self.current_address_index]
            self.display_address_from_cache(address)
    
    def next_address(self):
        """Navigate to the next address in the cache"""
        if self.current_address_index < len(self.cached_addresses) - 1:
            self.current_address_index += 1
            address = self.cached_addresses[self.current_address_index]
            self.display_address_from_cache(address)
    
    def display_address_from_cache(self, address):
        """Display an address from cache without adding it again"""
        self.address_var.set(address)
        self.update_navigation_buttons()
        self.update_address_counter()
        
        # Update listbox selection
        self.address_listbox.selection_clear(0, tk.END)
        self.address_listbox.selection_set(self.current_address_index)
        self.address_listbox.see(self.current_address_index)
        
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
    
    def on_address_select(self, event):
        """Handle address selection from the listbox"""
        selection = self.address_listbox.curselection()
        if selection:
            index = selection[0]
            if 0 <= index < len(self.cached_addresses):
                self.current_address_index = index
                address = self.cached_addresses[index]
                self.display_address_from_cache(address)
                # Automatically copy address to clipboard
                self.copy_address_to_clipboard(address)
    
    def clear_cache(self):
        """Clear all cached addresses"""
        if self.cached_addresses:
            if messagebox.askyesno("Clear Cache", "Are you sure you want to clear all cached addresses?"):
                self.cached_addresses.clear()
                self.current_address_index = -1
                self.address_var.set("")
                self.qr_label.config(image="", text="No Bitcoin address detected")
                self.update_address_list()
                self.update_navigation_buttons()
                self.update_address_counter()
        else:
            messagebox.showinfo("Info", "Cache is already empty")
    
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
