#! /usr/bin/env python3

import tkinter as tk
from scapy.all import ARP, Ether, srp, IP, ICMP, send, sniff, sr1
import time

# ARP scan function
def arp_scan():
    subnet = subnet_entry.get()  # Get the subnet entered by the user
    if not subnet:
        result_text_arp.delete(1.0, tk.END)
        result_text_arp.insert(tk.END, "Please enter a valid subnet.\n")
        return
    arp_request = ARP(pdst=subnet)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    devices = []
    for sent, received in answered_list:
        devices.append(f"IP: {received.psrc}, MAC: {received.hwsrc}")
    
    result_text_arp.delete(1.0, tk.END)
    if devices:
        result_text_arp.insert(tk.END, "Active devices in the network:\n")
        for device in devices:
            result_text_arp.insert(tk.END, device + "\n")
    else:
        result_text_arp.insert(tk.END, "No active devices found.\n")

# Packet sniffing function
def packet_analysis():
    filter_protocol = protocol_entry.get().strip()
    if not filter_protocol:
        filter_protocol = None
    result_text_packets.delete(1.0, tk.END)
    result_text_packets.insert(tk.END, f"\nSniffing packets with protocol: {filter_protocol}\n")
    packets = sniff(filter=filter_protocol, count=10)
    for i, packet in enumerate(packets, 1):
        result_text_packets.insert(tk.END, f"Packet {i}: {packet.summary()}\n")

# Send ICMP packet
def send_icmp():
    target_ip = target_ip_entry.get().strip()
    if not target_ip:
        result_text_icmp.delete(1.0, tk.END)
        result_text_icmp.insert(tk.END, "Please enter a valid IP address.\n")
        return
    result_text_icmp.delete(1.0, tk.END)
    result_text_icmp.insert(tk.END, f"Sending ICMP packet to {target_ip}...\n")
    packet = IP(dst=target_ip) / ICMP()
    send(packet, verbose=False)
    result_text_icmp.insert(tk.END, "ICMP packet sent!\n")

# Measure latency to a target IP
def measure_latency():
    target_ip = target_ip_entry.get().strip()
    if not target_ip:
        result_text_latency.delete(1.0, tk.END)
        result_text_latency.insert(tk.END, "Please enter a valid IP address.\n")
        return

    result_text_latency.delete(1.0, tk.END)
    result_text_latency.insert(tk.END, f"Sending ICMP packet to {target_ip}...\n")
    
    # Create an ICMP packet
    packet = IP(dst=target_ip) / ICMP()
    
    try:
        # Record the start time
        start_time = time.time()
        
        # Send the packet and wait for a reply
        response = sr1(packet, timeout=2, verbose=False)
        
        # Record the end time
        end_time = time.time()
        
        if response:
            latency = (end_time - start_time) * 1000  # Convert to milliseconds
            result_text_latency.insert(tk.END, f"Latency to {target_ip}: {latency:.2f} ms\n")
        else:
            result_text_latency.insert(tk.END, f"No response from {target_ip}. Host might be unreachable.\n")
    except Exception as e:
        result_text_latency.insert(tk.END, f"Error occurred: {e}\n")
# Log packets to a file
def log_packets():
    filter_protocol = protocol_entry.get().strip()
    if not filter_protocol:
        filter_protocol = None
    result_text_log.delete(1.0, tk.END)
    result_text_log.insert(tk.END, f"\nLogging packets with protocol: {filter_protocol}\n")
    packets = sniff(filter=filter_protocol, count=10)
    with open("packet_log.txt", "w") as log_file:
        for packet in packets:
            log_file.write(f"{time.time()} - {packet.summary()}\n")
    result_text_log.insert(tk.END, "Packets successfully logged to 'packet_log.txt'.\n")

# Set up the graphical interface
root = tk.Tk()
root.title("Network Scanner Tool")
root.geometry("600x600")

# Welcome message
welcome_label = tk.Label(root, text="Welcome to the Network Scanner Tool!", font=("Arial", 14))
welcome_label.pack(pady=10)

# Create a frame for network tasks
frame_tasks = tk.Frame(root)
frame_tasks.pack(pady=20)

# Subnet input (for ARP scan)
subnet_label = tk.Label(frame_tasks, text="Enter subnet (e.g., 192.168.1.0/24):")
subnet_label.grid(row=0, column=0, padx=5, pady=5)
subnet_entry = tk.Entry(frame_tasks, width=30)
subnet_entry.grid(row=0, column=1, padx=5, pady=5)

# Target IP input (for ICMP and latency measurement)
target_ip_label = tk.Label(frame_tasks, text="Enter target IP address:")
target_ip_label.grid(row=1, column=0, padx=5, pady=5)
target_ip_entry = tk.Entry(frame_tasks, width=30)
target_ip_entry.grid(row=1, column=1, padx=5, pady=5)

# Protocol input (for packet sniffing)
protocol_label = tk.Label(frame_tasks, text="Enter protocol (tcp, udp, icmp, or leave empty):")
protocol_label.grid(row=2, column=0, padx=5, pady=5)
protocol_entry = tk.Entry(frame_tasks, width=30)
protocol_entry.grid(row=2, column=1, padx=5, pady=5)

# Buttons for each task
arp_scan_button = tk.Button(frame_tasks, text="Start ARP Scan", command=arp_scan)
arp_scan_button.grid(row=3, column=0, padx=5, pady=5)

icmp_button = tk.Button(frame_tasks, text="Send ICMP Packet", command=send_icmp)
icmp_button.grid(row=3, column=1, padx=5, pady=5)

latency_button = tk.Button(frame_tasks, text="Measure Latency", command=measure_latency)
latency_button.grid(row=4, column=0, padx=5, pady=5)

packet_analysis_button = tk.Button(frame_tasks, text="Sniff Packets", command=packet_analysis)
packet_analysis_button.grid(row=4, column=1, padx=5, pady=5)

log_button = tk.Button(frame_tasks, text="Log Packets", command=log_packets)
log_button.grid(row=5, column=0, padx=5, pady=5)

# Create a frame for displaying results
frame_results = tk.Frame(root)
frame_results.pack(pady=10)

# ARP scan results
result_text_arp = tk.Text(frame_results, width=70, height=5)
result_text_arp.grid(row=0, column=0, padx=5, pady=5)

# ICMP results
result_text_icmp = tk.Text(frame_results, width=70, height=5)
result_text_icmp.grid(row=1, column=0, padx=5, pady=5)

# Latency results
result_text_latency = tk.Text(frame_results, width=70, height=5)
result_text_latency.grid(row=2, column=0, padx=5, pady=5)

# Packet sniffing results
result_text_packets = tk.Text(frame_results, width=70, height=5)
result_text_packets.grid(row=3, column=0, padx=5, pady=5)

# Packet logging results
result_text_log = tk.Text(frame_results, width=70, height=5)
result_text_log.grid(row=4, column=0, padx=5, pady=5)

# Run the window
root.mainloop()

