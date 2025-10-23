# Salva come server_echo.py e avvialo su localhost
import socket

HOST = '127.0.0.1'
PORT = 5000

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"Server in ascolto su {HOST}:{PORT}")
    conn, addr = s.accept()
    with conn:
        print('Connessione da', addr)
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print("Ricevuto:", data.decode('utf-8', errors='replace'))
            conn.sendall(b"Echo: " + data)
