# -*- coding: utf-8 -*-
# Eseguire in Python2
#porta 8000
import socket
import sys
import signal

def signal_handler(sig, frame):
    print("\nInterrotto dall'utente.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def connect_to_server(server_ip, server_port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (server_ip, server_port)
        print("Connessione a {} porta {}".format(server_ip, server_port))
        sock.connect(server_address)

        try:
            while True:
                message = raw_input("Inserisci un messaggio da inviare (o 'exit' per uscire): ")
                if message.lower() == 'exit':
                    print("Chiusura connessione...")
                    break

                print("Invio: {}".format(message))
                sock.sendall(message)  # in Python2 invia la stringa così com'è

                # Ricezione della risposta dal server
                while True:
                    data = sock.recv(1024)
                    if not data:
                        print("Connessione chiusa dal server.")
                        return
                    print("Risposta dal server: {}".format(data))
                    if len(data) < 1024:
                        break

        finally:
            sock.close()
            print("Connessione chiusa.")
    except Exception as e:
        print("Errore: {}".format(e))
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python client.py [indirizzo_ip_server] [porta_server]")
        sys.exit(1)

    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    connect_to_server(server_ip, server_port)
