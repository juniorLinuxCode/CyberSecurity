#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
P2P Multicast + TCP con gestione connessioni, log e discovery peer.
Ogni parte è commentata per spiegare cosa fa e perché.
"""
import argparse
import queue
import socket
import socketserver
import threading
import time
import sys
from typing import Dict, Tuple, Optional, List

# ---------------- Configurazioni principali -----------------------------------
MCAST_GRP = "239.255.0.1"        # IP multicast per discovery peer
MCAST_PORT = 9999                # Porta multicast
MCAST_TTL = 1                    # Limite pacchetto multicast (1 = LAN locale)
DISCOVER_INTERVAL = 5.0          # Ogni quanti secondi inviare pacchetto DISCOVER
IDLE_TIMEOUT = 300                # Timeout connessione inattiva in secondi
DEFAULT_SEND_WAIT_TIMEOUT = 5.0  # Timeout di attesa risposta messaggi

ConnID = int                     # Alias per identificatore connessione
Addr = Tuple[str, int]           # Alias per indirizzo (IP, porta)

# Lista peer noti da usare come bootstrap (default)
DEFAULT_BOOTSTRAP_IPS = [
    "192.168.58.143",
    "192.168.58.2",
    "192.168.58.1",
    "192.168.58.137",
    "192.168.58.139",
    "192.168.58.140",
    "192.168.58.254",
]
DEFAULT_BOOTSTRAP_PORT = 8000

LOG_PROMPT = "p2p-mcast> "        # Prompt per log interattivo (opzionale)

# ---------------- Logging sicuro per thread ----------------------------------
_buffer_lock = threading.Lock()    # Lock per proteggere buffer log
_buffered_logs: List[str] = []     # Buffer dei log
_write_lock = threading.Lock()     # Lock per scrittura su stdout/stderr

def buffered_log(msg: str) -> None:
    """Aggiunge messaggio al buffer dei log con timestamp"""
    ts = time.strftime("%H:%M:%S")
    entry = f"[{ts}] {msg}"
    with _buffer_lock:
        _buffered_logs.append(entry)

def flush_logs() -> None:
    """Stampa tutti i log buffered in modo thread-safe"""
    with _buffer_lock:
        if not _buffered_logs:
            return
        to_print = _buffered_logs[:]
        _buffered_logs.clear()
    with _write_lock:
        for line in to_print:
            sys.stdout.write(line + "\n")
        sys.stdout.flush()

def server_log(msg: str) -> None:
    """Stampa log del server direttamente su stderr"""
    ts = time.strftime("%H:%M:%S")
    entry = f"[{ts}] {msg}"
    with _write_lock:
        sys.stderr.write(entry + "\n")
        sys.stderr.flush()

def log_critical(msg: str) -> None:
    """Messaggi critici su stdout"""
    with _write_lock:
        sys.stdout.write("\n" + msg + "\n")
        sys.stdout.flush()

# ---------------- Registro connessioni ----------------------------------------
class ConnectionRegistry:
    """
    Tiene traccia di tutte le connessioni in/out con ID univoco.
    Gestisce anche code thread-safe per messaggi.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._next_id = 1
        # dizionario connessioni: id -> (socket, addr, incoming?, last_touch)
        self._conns: Dict[ConnID, Tuple[socket.socket, Addr, bool, float]] = {}
        # code messaggi per ogni connessione
        self._msg_queues: Dict[ConnID, "queue.Queue[str]"] = {}

    def add(self, sock: socket.socket, addr: Addr, incoming: bool) -> ConnID:
        """Aggiunge una nuova connessione e restituisce il suo ID"""
        with self._lock:
            cid = self._next_id
            self._next_id += 1
            self._conns[cid] = (sock, addr, incoming, time.time())
            self._msg_queues[cid] = queue.Queue()
            return cid

    def touch(self, cid: ConnID) -> None:
        """Aggiorna timestamp ultima attività per connessione"""
        with self._lock:
            if cid in self._conns:
                sock, addr, incoming, _ = self._conns[cid]
                self._conns[cid] = (sock, addr, incoming, time.time())

    def remove(self, cid: ConnID) -> None:
        """Rimuove e chiude connessione"""
        with self._lock:
            if cid in self._conns:
                sock, _, _, _ = self._conns.pop(cid)
                self._msg_queues.pop(cid, None)
                try:
                    sock.close()
                except Exception:
                    pass

    def items(self):
        """Ritorna lista (id, connessione)"""
        with self._lock:
            return list(self._conns.items())

    def get(self, cid: ConnID):
        """Ritorna tuple connessione per id"""
        with self._lock:
            return self._conns.get(cid)

    def find_by_addr(self, addr: Addr):
        """Trova connessione per indirizzo IP/porta"""
        with self._lock:
            for cid, (_, a, _, _) in self._conns.items():
                if a == addr:
                    return cid
        return None

    def find_idle(self, idle_threshold: float):
        """Ritorna connessioni inattive oltre soglia"""
        now = time.time()
        idle = []
        with self._lock:
            for cid, (_, addr, _, last) in self._conns.items():
                if now - last > idle_threshold:
                    idle.append((cid, addr))
        return idle

    def push_msg(self, cid: ConnID, msg: str) -> None:
        """Aggiunge messaggio alla coda della connessione"""
        with self._lock:
            q = self._msg_queues.get(cid)
        if q:
            try:
                q.put_nowait(msg)
            except queue.Full:
                pass

    def pop_msg(self, cid: ConnID, timeout: Optional[float] = None) -> Optional[str]:
        """Estrae messaggio dalla coda della connessione (attesa opzionale)"""
        with self._lock:
            q = self._msg_queues.get(cid)
        if not q:
            return None
        try:
            return q.get(timeout=timeout)
        except queue.Empty:
            return None

# ---------------- Handler TCP -------------------------------------------------
class P2PRequestHandler(socketserver.BaseRequestHandler):
    """
    Gestisce ogni connessione TCP IN in un thread separato
    """
    def handle(self):
        peer = getattr(self.server, "peer_instance", None)
        addr = self.client_address
        tname = threading.current_thread().name

        if peer is None:
            server_log(f"[{tname}] Handler senza riferimento al Peer; chiudo.")
            return

        cid = peer.registry.add(self.request, addr, incoming=True)
        server_log(f"[{tname}] Connessione IN registrata: id={cid} addr={addr}")

        try:
            while True:
                data = self.request.recv(4096)
                if not data:
                    break  # connessione chiusa dal peer
                peer.registry.touch(cid)  # aggiorna timestamp attività
                try:
                    message = data.decode("utf-8", errors="replace").rstrip("\n")
                except Exception:
                    message = repr(data)
                peer.registry.push_msg(cid, message)
                server_log(f"[{tname}] Ricevuto da {addr} (id={cid}): {message}")
                # esempio di risposta semplice
                response = message.upper()
                try:
                    self.request.sendall(response.encode("utf-8"))
                except Exception as e:
                    server_log(f"[{tname}] Errore invio a id={cid}: {e}")
                    break
        except Exception as e:
            server_log(f"[{tname}] Errore gestione connessione {addr}: {e}")
        finally:
            server_log(f"[{tname}] Chiusura IN id={cid} addr={addr}")
            peer.registry.remove(cid)

# ---------------- Classe Peer -------------------------------------------------
class Peer:
    """
    Ogni istanza rappresenta un nodo P2P.
    Contiene server TCP, socket multicast e gestione connessioni.
    """
    def __init__(
        self,
        host: str,
        port: int,
        bootstrap: Optional[List[Tuple[str, int]]] = None,
        mcast_group: str = MCAST_GRP,
        mcast_port: int = MCAST_PORT,
        discover_interval: float = DISCOVER_INTERVAL,
        idle_timeout: int = IDLE_TIMEOUT,
        send_wait_timeout: float = DEFAULT_SEND_WAIT_TIMEOUT,
    ):
        self.host = host
        self.port = port
        self.registry = ConnectionRegistry()
        self.server = None
        self._server_thread = None
        self._stop_event = threading.Event()

        self.mcast_group = mcast_group
        self.mcast_port = mcast_port
        self._mcast_sock = None
        self._mcast_thread = None
        self._announcer_thread = None
        self.discover_interval = discover_interval

        self.bootstrap = bootstrap or []
        self.idle_timeout = idle_timeout
        self._idle_thread = None

        self.send_wait_timeout = float(send_wait_timeout)

    # ---------------- Server TCP ----------------
    def start_server(self):
        """
        Avvia server TCP per connessioni in entrata.
        Ogni connessione viene gestita in un thread separato da P2PRequestHandler.
        """
        class _Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True

        try:
            self.server = _Server((self.host, self.port), P2PRequestHandler)
        except Exception as e:
            buffered_log(f"[server] Impossibile avviare server su {self.host}:{self.port}: {e}")
            raise
        setattr(self.server, "peer_instance", self)

        def serve():
            server_log(f"[server] Peer in ascolto su {self.host}:{self.port}")
            try:
                self.server.serve_forever(poll_interval=0.5)
            except Exception as e:
                server_log(f"[server] Terminated: {e}")

        self._server_thread = threading.Thread(target=serve, name="p2p-server", daemon=True)
        self._server_thread.start()

    def stop_server(self):
        """Chiude server e tutte le connessioni"""
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass
        self._stop_event.set()
        for cid, (sock, _, _, _) in self.registry.items():
            try:
                sock.close()
            except Exception:
                pass
            self.registry.remove(cid)

    # ---------------- Connessioni Out ----------------
    def _should_initiate(self, remote: Addr) -> bool:
        """Regola anti-duplicato: solo un peer avvia la connessione"""
        return (self.host, self.port) < remote

    def connect(self, ip: str, port: int, timeout: float = 3.0) -> Optional[ConnID]:
        """Crea connessione TCP OUT verso un altro peer"""
        if ip == self.host and port == self.port:
            raise ConnectionError("Tentativo connessione verso se stessi; ignorato.")
        if self.registry.find_by_addr((ip, port)) is not None:
            return None  # già connesso
        if not self._should_initiate((ip, port)):
            raise ConnectionError("Regola anti-duplicato: non avviare connessione verso peer con ordine minore/uguale.")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
        except Exception as e:
            sock.close()
            raise ConnectionError(f"Connessione fallita a {ip}:{port}: {e}")
        cid = self.registry.add(sock, (ip, port), incoming=False)
        t = threading.Thread(target=self._listen_outgoing, args=(cid,), name=f"out-{cid}", daemon=True)
        t.start()
        server_log(f"[peer] Connessione OUT stabilita id={cid} addr={(ip,port)}")
        return cid

    def _listen_outgoing(self, cid: ConnID):
        """Ascolta messaggi dalle connessioni OUT in un thread dedicato"""
        entry = self.registry.get(cid)
        if not entry:
            return
        sock, addr, _, _ = entry
        tname = threading.current_thread().name
        try:
            sock.settimeout(1.0)
            while not self._stop_event.is_set():
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not data:
                    break
                self.registry.touch(cid)
                try:
                    msg = data.decode("utf-8", errors="replace").rstrip("\n")
                except Exception:
                    msg = repr(data)
                self.registry.push_msg(cid, msg)
                server_log(f"[{tname}] Ricevuto da {addr} (id={cid}): {msg}")
        except Exception as e:
            server_log(f"[{tname}] Errore ascolto id={cid}: {e}")
        finally:
            server_log(f"[{tname}] Connessione OUT id={cid} chiusa")
            self.registry.remove(cid)

    # ---------------- Invio messaggi ----------------
    def send(self, cid: ConnID, message: str):
        """Invia messaggio a connessione specifica"""
        entry = self.registry.get(cid)
        if not entry:
            raise KeyError("Connessione non trovata")
        sock, addr, _, _ = entry
        try:
            sock.sendall(message.encode("utf-8"))
            self.registry.touch(cid)
        except Exception as e:
            raise ConnectionError(f"Invio fallito su {addr}: {e}")

    def send_and_wait(self, cid: ConnID, message: str, timeout: Optional[float] = None) -> Optional[str]:
        """Invia messaggio e aspetta risposta (opzionale timeout)"""
        self.send(cid, message)
        use_to = timeout if (timeout is not None) else self.send_wait_timeout
        return self.registry.pop_msg(cid, timeout=use_to)

    def broadcast(self, message: str):
        """Invia messaggio a tutti i peer connessi"""
        for cid, (sock, addr, _, _) in self.registry.items():
            try:
                sock.sendall(message.encode("utf-8"))
                self.registry.touch(cid)
            except Exception as e:
                server_log(f"[broadcast] Errore invio a {addr}: {e}")

    def list_peers(self):
        """Ritorna lista dei peer connessi con info base"""
        rows = []
        for cid, (sock, addr, incoming, last) in self.registry.items():
            rows.append((cid, addr, "in" if incoming else "out", int(time.time() - last)))
        return rows

    # ---------------- Multicast discovery ---------------------------------
    def _create_mcast_socket(self):
        """Crea socket UDP multicast per discovery"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", self.mcast_port))
        except Exception as e:
            sock.close()
            raise RuntimeError(f"Bind multicast fallito: {e}")
        try:
            mreq = socket.inet_aton(self.mcast_group) + socket.inet_aton(self.host)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except Exception as e:
            sock.close()
            raise RuntimeError(f"Join multicast fallito: {e}")
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MCAST_TTL)
        sock.settimeout(1.0)
        return sock

    def start_discovery(self):
        """
        Avvia listener e announcer multicast in thread separati.
        Permette ai peer di scoprirsi automaticamente.
        """
        try:
            self._mcast_sock = self._create_mcast_socket()
        except Exception as e:
            buffered_log(f"[mcast] Impossibile inizializzare multicast: {e}")
            return

        # Thread per ascolto multicast
        def listen():
            tn = threading.current_thread().name
            server_log(f"[{tn}] Ascolto multicast {self.mcast_group}:{self.mcast_port} iface={self.host}")
            while not self._stop_event.is_set():
                try:
                    data, addr = self._mcast_sock.recvfrom(1024)
                except socket.timeout:
                    continue
                except Exception as e:
                    server_log(f"[{tn}] Errore recvfrom: {e}")
                    break
                try:
                    text = data.decode("utf-8", errors="replace").strip()
                except Exception:
                    text = repr(data)
                parts = text.split()
                if len(parts) >= 3 and parts[0] == "DISCOVER":
                    peer_ip = parts[1]
                    try:
                        peer_port = int(parts[2])
                    except Exception:
                        continue
                    if peer_ip == self.host and peer_port == self.port:
                        continue
                    if self.registry.find_by_addr((peer_ip, peer_port)) is None:
                        if self._should_initiate((peer_ip, peer_port)):
                            server_log(f"[{tn}] Scoperto peer {peer_ip}:{peer_port} -> provo connessione")
                            try:
                                self.connect(peer_ip, peer_port)
                            except Exception as e:
                                server_log(f"[{tn}] Connessione fallita a {peer_ip}:{peer_port}: {e}")
                        else:
                            server_log(f"[{tn}] Scoperto peer {peer_ip}:{peer_port} -> attendo connessione IN (anti-duplica)")

        # Thread per invio periodico multicast
        def announce():
            tn = threading.current_thread().name
            try:
                send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(self.host))
                send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MCAST_TTL)
                while not self._stop_event.is_set():
                    msg = f"DISCOVER {self.host
