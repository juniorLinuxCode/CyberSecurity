#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
syn_scan_aperta.py
Scansione ICMP + SYN multiporta con output solo per porte aperte.
Uso: sudo python3 syn_scan_aperta.py <IP> <PORTA> oppure <IP> <PORTA_INIZIO>-<PORTA_FINE>
"""

from scapy.all import IP, ICMP, TCP, sr1, conf
import sys
import random
import time

conf.verb = 0  # Disattiva output verboso di Scapy

def icmp_probe(ip: str, timeout: int = 2) -> bool:
    pkt = IP(dst=ip) / ICMP()
    resp = sr1(pkt, timeout=timeout)
    return resp is not None

def syn_scan(ip: str, port: int, timeout: float = 0.5):
    sport = random.randint(1025, 65535)
    syn_pkt = IP(dst=ip) / TCP(sport=sport, dport=port, flags='S')
    resp = sr1(syn_pkt, timeout=timeout)
    return resp

def main():
    if len(sys.argv) != 3:
        print("Uso: sudo python3 syn_scan_aperta.py <IP> <PORTA> oppure <IP> <PORTA_INIZIO>-<PORTA_FINE>")
        sys.exit(1)

    ip = sys.argv[1]
    port_input = sys.argv[2]

    if '-' in port_input:
        try:
            start_port, end_port = map(int, port_input.split('-'))
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                raise ValueError
            ports = range(start_port, end_port + 1)
        except ValueError:
            print("Errore: intervallo porte non valido.")
            sys.exit(1)
    else:
        try:
            port = int(port_input)
            if port < 1 or port > 65535:
                raise ValueError
            ports = [port]
        except ValueError:
            print("Errore: la porta deve essere un numero intero tra 1 e 65535.")
            sys.exit(1)

    print(f"[+] ICMP probe verso {ip} ...")
    if not icmp_probe(ip):
        print("[-] Nessuna risposta ICMP. Host non raggiungibile o ICMP bloccato.")
        sys.exit(1)

    print(f"[+] Host raggiungibile. Avvio SYN scan sulle porte: {ports.start if isinstance(ports, range) else ports} ...")

    aperte = []

    for port in ports:
        resp = syn_scan(ip, port)
        time.sleep(0.01)  # Pausa breve tra pacchetti

        if resp and resp.haslayer(TCP):
            try:
                flags_value = int(resp.getlayer(TCP).flags)
            except Exception:
                continue

            if flags_value == 0x12:  # SYN+ACK
                aperte.append(port)
                print(f"[{port}] Aperta")

    print("\n=== Porte aperte ===")
    if aperte:
        print(f"{len(aperte)} porte aperte trovate: {aperte}")
    else:
        print("Nessuna porta aperta trovata.")

if __name__ == "__main__":
    main()

#per eseguire il codice inserire l'ip dell attaccante e il numero delle porte da scansionare
#fino a 65535 porte
# ad esempio: 1.1.1.1 1-65535