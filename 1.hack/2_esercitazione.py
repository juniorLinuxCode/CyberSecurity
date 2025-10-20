from scapy.all import IP, ICMP,sr1

pacchetto=IP(dst="192.168.19.133") / ICMP ()/ "Messaggio di prova"

risposta= sr1(pacchetto, timeout=2)

if risposta:
    if hasattr (risposta, "load"):
        print("Pacchetto ricevuto", risposta.load)
    else:
        print("nessun payload ricevuto")
    
else:
    print("nessuna risposta ricvevuta")