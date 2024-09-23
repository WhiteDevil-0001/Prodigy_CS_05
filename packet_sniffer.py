import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff
import threading

# Global variable to control the sniffing loop
sniffing_active = False

# Function to process and display packet details
def process_packet(packet):
    if sniffing_active:
        try:
            src_ip = packet[0][1].src
            dst_ip = packet[0][1].dst
            protocol = packet[0][1].proto
            payload = bytes(packet[0][1].payload).hex()

            # Insert packet information in the text area
            text_area.insert(tk.END, f"Source IP: {src_ip}\n")
            text_area.insert(tk.END, f"Destination IP: {dst_ip}\n")
            text_area.insert(tk.END, f"Protocol: {protocol}\n")
            text_area.insert(tk.END, f"Payload (hex): {payload[:100]}...\n")  # Limiting payload display to 100 chars
            text_area.insert(tk.END, '-' * 50 + '\n')

            # Scroll to the bottom of the text area
            text_area.yview(tk.END)
        except:
            pass

# Function to start sniffing packets
def start_sniffing():
    sniff(prn=process_packet, store=0)

# Function to control sniffer thread
def start_sniffer_thread():
    global sniffing_active
    sniffing_active = True
    status_label.config(text="Sniffer Status: RUNNING", fg="green")
    threading.Thread(target=start_sniffing, daemon=True).start()

# Function to stop the sniffer
def stop_sniffer():
    global sniffing_active
    sniffing_active = False
    status_label.config(text="Sniffer Status: STOPPED", fg="red")

# Function to clear the text area
def clear_output():
    text_area.delete(1.0, tk.END)

# Set up the GUI
root = tk.Tk()
root.title("Packet Sniffer")

# Text area to display captured packets
text_area = scrolledtext.ScrolledText(root, width=80, height=20)
text_area.pack()

# Status label to display if the sniffer is running or stopped
status_label = tk.Label(root, text="Sniffer Status: STOPPED", fg="red")
status_label.pack(pady=5)

# Start Sniffer button
start_button = tk.Button(root, text="Start Sniffer", command=start_sniffer_thread)
start_button.pack(side=tk.LEFT, padx=10, pady=10)

# Stop Sniffer button
stop_button = tk.Button(root, text="Stop Sniffer", command=stop_sniffer)
stop_button.pack(side=tk.LEFT, padx=10, pady=10)

# Clear Output button
clear_button = tk.Button(root, text="Clear Output", command=clear_output)
clear_button.pack(side=tk.RIGHT, padx=10, pady=10)

# Start the GUI event loop
root.mainloop()
