# === Linux MAC Address Changer ===
#
# Description:
# This script changes the MAC (Media Access Control) address of a specified network
# interface on a Linux system. This process is commonly known as "MAC spoofing".
#
# How it works:
# It uses the `subprocess` module to execute a sequence of shell commands that
# are part of the `iproute2` package, which is standard on modern Linux distributions.
# 1.  It takes the target network interface down (`ip link set <interface> down`),
#     as the MAC address usually cannot be changed while the interface is active.
# 2.  It sets the new, custom MAC address (`ip link set <interface> address <new_mac>`).
# 3.  It brings the network interface back up (`ip link set <interface> up`).
#
# Dependencies:
# - Python 3 Standard Library (`subprocess`).
# - A Linux operating system.
# - The `iproute2` package (which provides the `ip` command), pre-installed on most
#   modern Linux systems.
#
# !! IMPORTANT !!
# - This script MUST be run with root privileges (e.g., using `sudo python3 mac_changer.py`).
# - The commands used are specific to Linux and will NOT work on Windows or macOS.
# - Changing your MAC address can cause network connectivity issues. Use with caution.

import subprocess

# --- Configuration ---
# The network interface you want to modify (e.g., "eth0", "wlan0").
# You can find your interface name by running the command `ip a` or `ifconfig`.
interface = "eth0"

# The new MAC address you want to assign.
new_mac_address = "2a:1b:22:3c:4d:ef"
# ---------------------

def change_mac_address(target_interface, new_mac):
    """
    Disables the network interface, changes its MAC address, and re-enables it.
    """
    print(f"[*] Disabling network interface: {target_interface}")
    subprocess.run(["ip", "link", "set", target_interface, "down"])

    print(f"[*] Changing MAC address for {target_interface} to {new_mac}")
    subprocess.run(["ip", "link", "set", target_interface, "address", new_mac])

    print(f"[*] Re-enabling network interface: {target_interface}")
    subprocess.run(["ip", "link", "set", target_interface, "up"])
    
    print(f"\n[+] MAC address for {target_interface} has been changed to {new_mac}")


if __name__ == "__main__":
    change_mac_address(interface, new_mac_address)