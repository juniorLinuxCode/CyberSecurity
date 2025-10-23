#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
syn_scan_os_interattivo.py
Scansione SYN multiporta interattiva con rilevamento del sistema operativo remoto (una sola volta).
"""

from scapy.all import IP, TCP, sr1, conf
import random
import time

conf.verb = 0  # Disattiva output verboso

MODALITA = {
    "veloce": {
        "timeout": 0.3,
        "delay": 0.0,
        "shuffle": False,
        "descrizione": "Scansione rapida senza pause. Più visibile in rete."
    },
    "normale": {
        "timeout": 0.5,
        "delay": 0.01,
        "shuffle": False,
        "descrizione": "Scansione bilanciata con pausa breve tra pacchetti."
    },
    "silenziosa": {
        "timeout": 1.0,
        "delay": 0.1,
        "shuffle": True,
        "descrizione": "Scansione stealth: ordine casuale, pause lunghe, niente ICMP. Meno rilevabile da IDS/IPS."
    },
    "completa": {
        "timeout": 0.5,
        "delay": 0.01,
        "shuffle": False,
        "descrizione": "Scansione di tutte le 65535 porte. ⚠️ Molto lunga."
    }
}

def syn_scan(ip: str, port: int, timeout: float):
    sport = random.randint(1025, 65535)
    pkt = IP(dst=ip) / TCP(sport=sport, dport=port, flags='S')
    return sr1(pkt, timeout=timeout)

def fingerprint_os(resp) -> str:
    if not resp.haslayer(IP) or not resp.haslayer(TCP):
        return "Impossibile identificare l'OS"

    ttl = resp[IP].ttl
    win = resp[TCP].window

    if ttl >= 128:
        if win == 64240:
            return "Probabile: Windows 10/11"
        elif win == 8192:
            return "Probabile: Windows XP/2000"
        else:
            return "Probabile: Windows (versione incerta)"
    elif ttl >= 64:
        if win == 5840:
            return "Probabile: Linux (kernel 2.4/2.6)"
        elif win == 14600:
            return "Probabile: Linux moderno"
        else:
            return "Probabile: Linux/Unix"
    elif ttl >= 255:
        return "Probabile: Cisco/FreeBSD/Network device"
    else:
        return "OS non identificabile con certezza"

def main():
    print("\n" + "="*60)
    print("=== Scansione SYN Multiporta + OS Fingerprinting ===")
    print("="*60 + "\n")

    ip = input("🔹 Inserisci l'indirizzo IP da scansionare: ").strip()

    print("\n🔹 Scegli la modalità di scansione:")
    for i, nome in enumerate(MODALITA.keys(), start=1):
        print(f" {i} - {nome:<10} → {MODALITA[nome]['descrizione']}")
    scelta = input("\nInserisci il numero della modalità: ").strip()

    modalita = None
    if scelta == "1":
        modalita = "veloce"
    elif scelta == "2":
        modalita = "normale"
    elif scelta == "3":
        modalita = "silenziosa"
    elif scelta == "4":
        modalita = "completa"
    else:
        print("❌ Scelta non valida.")
        return

    config = MODALITA[modalita]
    timeout = config["timeout"]
    delay = config["delay"]
    shuffle = config["shuffle"]

    if modalita == "completa":
        ports = list(range(1, 65536))
    else:
        porta_input = input("\n🔹 Inserisci le porte da scansionare (es: 22,80,443 o 20-100): ").strip()
        if '-' in porta_input:
            try:
                start, end = map(int, porta_input.split('-'))
                ports = list(range(start, end + 1))
            except:
                print("❌ Intervallo non valido.")
                return
        else:
            try:
                ports = [int(p) for p in porta_input.split(',')]
            except:
                print("❌ Formato porte non valido.")
                return

    if shuffle:
        random.shuffle(ports)

    print(f"\n[+] Avvio scansione '{modalita}' su {len(ports)} porte...")
    print(f"[i] {MODALITA[modalita]['descrizione']}\n")

    aperte = []
    primo_pacchetto = None

    for port in ports:
        resp = syn_scan(ip, port, timeout)
        time.sleep(delay)

        if resp and resp.haslayer(TCP):
            try:
                flags = int(resp.getlayer(TCP).flags)
                if flags == 0x12:  # SYN+ACK
                    aperte.append(port)
                    print(f"[{port}] Aperta")
                    if not primo_pacchetto:
                        primo_pacchetto = resp
            except:
                continue

    print("\n=== Riepilogo Porte Aperte ===")
    if aperte:
        print(f"{len(aperte)} porte aperte trovate: {aperte}")
    else:
        print("Nessuna porta aperta trovata.")

    if primo_pacchetto:
        os_guess = fingerprint_os(primo_pacchetto)
        print(f"\n🧠 Sistema operativo stimato: {os_guess}")

if __name__ == "__main__":
    main()
