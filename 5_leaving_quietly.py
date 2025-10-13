# Import required functions from Scapy
# Avviare prima 4_esercitazionespoofing  dopo questo.

from scapy.all import ARP, send

# Function to restore ARP tables (used as a post-spoofing mitigation)
def leaving_quietly():
    # --- Restore the router's ARP table ---
    # We create an ARP packet to send the correct mapping to the router's ARP cache
    arp_response = ARP()
    
    # Set ARP operation type: 2 means 'ARP reply'
    arp_response.op = 2
    
    # Set the IP address of the router as the target
    arp_response.pdst = "192.168.19.2"  # Router's IP address
    
    # Set the MAC address of the router as the target hardware address
    arp_response.hwdst = "00:50:56:f8:eb:35"  # Router's MAC address
    
    # Set the real MAC address of the victim (so the router learns the correct binding)
    arp_response.hwsrc = "00:0c:29:db:03:fe"  # Victim's MAC address
    
    # Set the victim's IP address as the source IP
    arp_response.psrc = "192.168.19.128"  # Victim's IP address
    sudo 
    # Send the ARP packet to the router to fix its ARP table
    send(arp_response)

    # --- Restore the victim's ARP table (typically Windows) ---
    # Create another ARP reply to inform the victim of the correct router MAC
    arp_response = ARP()
    
    # Again, set operation type to ARP reply
    arp_response.op = 2
    
    # Set the victim's IP address as the destination
    arp_response.pdst = "192.168.19.128"  # Victim's IP address
    
    # Set the victim's MAC address as the destination hardware
    arp_response.hwdst = "00:0c:29:db:03:fe"  # Victim's MAC address
    
    # Set the real MAC address of the router (to reestablish trust)
    arp_response.hwsrc = "00:50:56:f8:eb:35"  # Router's MAC address
    
    # Set the router's IP address as the source IP
    arp_response.psrc = "192.168.19.2"  # Router's IP address
    
    # Send the ARP packet to the victim to fix its ARP table
    send(arp_response)

# If the script is interrupted manually (e.g., with Ctrl+C), handle it gracefully
try:
    # Simulate the main program execution (e.g., ARP spoofing or MITM logic)
    while True:
        # This is where the attack logic would go (e.g., sending spoof packets)
        pass  # Placeholder for the active attack code
except KeyboardInterrupt as err:
    # When a keyboard interrupt occurs, restore the ARP tables
    leaving_quietly()
    print("Exiting... ARP tables have been restored.")