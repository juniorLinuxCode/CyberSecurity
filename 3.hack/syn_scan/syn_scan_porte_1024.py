#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
syn_scan_multiporta.py
Scansione ICMP + SYN multiporta con Scapy.
Uso: sudo python3 syn_scan_multiporta.py <IP> <PORTA> oppure <IP> <PORTA_INIZIO>-<PORTA_FINE>
"""

from scapy.all import IP, ICMP, TCP, sr1, conf
import sys
import random

# Disabilita output verboso di Scapy (evita stampe inutili durante la scansione)
conf.verb = 0

def icmp_probe(ip: str, timeout: int = 3) -> bool:
    """
    Verifica se l'host è raggiungibile tramite ICMP Echo Request (ping).
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
    # Controllo argomenti: IP + porta o intervallo
    if len(sys.argv) != 3:
        print("Uso: sudo python3 syn_scan_multiporta.py <IP> <PORTA> oppure <IP> <PORTA_INIZIO>-<PORTA_FINE>")
        sys.exit(1)

    ip = sys.argv[1]
    port_input = sys.argv[2]

    # Parsing dell'intervallo di porte
    if '-' in port_input:
        try:
            start_port, end_port = map(int, port_input.split('-'))
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                raise ValueError
            ports = range(start_port, end_port + 1)
        except ValueError:
            print("Errore: intervallo porte non valido. Usa formato <PORTA_INIZIO>-<PORTA_FINE>.")
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

    for port in ports:
        resp = syn_scan(ip, port)
        if resp is None:
            print(f"[{port}] Nessuna risposta TCP. Porta filtrata o bloccata.")
            continue

        if resp.haslayer(TCP):
            tcp_layer = resp.getlayer(TCP)
            flags_desc = interpret_tcp_flags(tcp_layer)
            try:
                flags_value = int(tcp_layer.flags)
            except Exception:
                flags_value = None

            if flags_value == 0x12:
                print(f"[{port}] Aperta (SYN+ACK).")
            elif flags_value == 0x14:
                print(f"[{port}] Chiusa (RST+ACK).")
            else:
                print(f"[{port}] Risposta TCP non standard: {flags_desc}")
        else:
            print(f"[{port}] Nessun layer TCP. Possibile errore ICMP.")
            resp.show()

if __name__ == "__main__":
    main()


# per utilizzarlo bisogna inserire l'ip dell'attaccante e le porte da scannerizzare
#massimo 1024 porte
# esempio 1.1.1.1 1-1024