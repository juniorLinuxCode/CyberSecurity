#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
syn_scan.py
Esempio didattico di probe ICMP + SYN scan con Scapy.
Uso: sudo python3 syn_scan.py <IP> <PORT>
"""

from scapy.all import IP, ICMP, TCP, sr1, conf
import sys
import random

# Disabilita output verboso di Scapy (utile per scansioni pulite)
conf.verb = 0

def icmp_probe(ip: str, timeout: int = 3) -> bool:
    """
    Invia un pacchetto ICMP Echo Request (ping) e verifica se l'host risponde.
    Ritorna True se riceve una risposta, False altrimenti.
    """
    pkt = IP(dst=ip) / ICMP()
    resp = sr1(pkt, timeout=timeout)
    return resp is not None

def syn_scan(ip: str, port: int, timeout: int = 3):
    """
    Invia un pacchetto TCP con flag SYN per verificare lo stato della porta.
    Ritorna il pacchetto di risposta oppure None.
    """
    sport = random.randint(1025, 65535)  # Porta sorgente casuale
    syn_pkt = IP(dst=ip) / TCP(sport=sport, dport=port, flags='S')
    resp = sr1(syn_pkt, timeout=timeout)
    return resp

def interpret_tcp_flags(tcp_layer) -> str:
    """
    Interpreta i flag TCP ricevuti e li descrive in modo leggibile.
    """
    flags = tcp_layer.flags
    try:
        flags_int = int(flags)
    except Exception:
        flags_int = None

    desc = []
    if flags_int is not None:
        if flags_int & 0x02: desc.append("SYN")
        if flags_int & 0x10: desc.append("ACK")
        if flags_int & 0x04: desc.append("RST")
        if flags_int & 0x01: desc.append("FIN")
        if flags_int & 0x08: desc.append("PSH")
        if flags_int & 0x20: desc.append("URG")
        if flags_int & 0x40: desc.append("ECE")
        if flags_int & 0x80: desc.append("CWR")
        return "+".join(desc) if desc else f"FLAG_RAW=0x{flags_int:02x}"
    else:
        return str(flags)

def main():
    if len(sys.argv) != 3:
        print("Uso corretto: sudo python3 syn_scan.py <IP> <PORT>")
        sys.exit(1)

    ip = sys.argv[1]
    try:
        port = int(sys.argv[2])
    except ValueError:
        print("Errore: la porta deve essere un numero intero.")
        sys.exit(1)

    print(f"[+] ICMP probe verso {ip} ...")
    if not icmp_probe(ip):
        print("[-] Nessuna risposta ICMP. Host non raggiungibile o ICMP bloccato.")
        sys.exit(1)

    print(f"[+] Host raggiungibile. Avvio SYN scan sulla porta {port} ...")
    resp = syn_scan(ip, port)

    if resp is None:
        print("[-] Nessuna risposta TCP. Porta filtrata o host non risponde.")
        sys.exit(0)

    if resp.haslayer(TCP):
        tcp_layer = resp.getlayer(TCP)
        flags_desc = interpret_tcp_flags(tcp_layer)
        print(f"[+] Risposta TCP ricevuta: flags = {tcp_layer.flags} -> {flags_desc}")

        try:
            flags_value = int(tcp_layer.flags)
        except Exception:
            flags_value = None

        if flags_value == 0x12:
            print(f"[OK] Porta {port} aperta (SYN+ACK).")
        elif flags_value == 0x14:
            print(f"[-] Porta {port} chiusa (RST+ACK).")
        else:
            print(f"[?] Risposta TCP non standard: flags = 0x{flags_value:02x}" if flags_value else "[?] Flags non interpretabili.")
    else:
        print("[-] Nessun layer TCP nella risposta. Possibile errore ICMP.")
        resp.show()

if __name__ == "__main__":
    main()

#per farlo partire inserire l'ip della macchina attaccante e le porte da scannerizzare 
#massimo porte sccanner 1024
#ad esempio 1.1.1.1 1  1-1024