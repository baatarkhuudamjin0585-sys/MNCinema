from http.server import BaseHTTPRequestHandler
import json
import os
import sys
import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta
import urllib.parse

# Vercel дээр /tmp хавтсанд SQLite бичих эрх байдаг
DB_PATH = "/tmp/database.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode('utf-8')).hexdigest()

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT,
        is_admin INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        expires_at TEXT,
        current_session_token TEXT,
        current_device_id TEXT,
        last_device_info TEXT,
        last_active_at TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS movies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        poster_url TEXT,
        video_url TEXT NOT NULL,
        duration TEXT,
        category TEXT DEFAULT 'Anime',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS access_passes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pass_key TEXT UNIQUE NOT NULL,
        note TEXT,
        days INTEGER DEFAULT 30,
        locked_device_id TEXT,
        locked_device_info TEXT,
        activated_at TEXT,
        expires_at TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    
    # Үндсэн админ шалгах
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        c.execute("INSERT INTO users (username, password_hash, name, is_admin) VALUES ('admin', ?, 'Администратор', 1)", (hash_pw("admin123"),))
    
    # Үндсэн кино шалгах (Bunny Stream Demon Slayer)
    c.execute("SELECT * FROM movies WHERE id = 1")
    if not c.fetchone():
        c.execute("""
        INSERT INTO movies (id, title, description, poster_url, video_url, duration)
        VALUES (1, 'Demon Slayer: Kimetsu no Yaiba - Infinity Castle', 'Монгол хадмалтай', 
                'https://images.unsplash.com/photo-1578632767115-351597cf2477?w=500', 
                'https://iframe.mediadelivery.net/embed/796263/42677ba9-9a48-424b-a289-828620ea3eb2', '2:34:42')
        """)
        
    conn.commit()
    conn.close()

# Эхлэхэд сан үүсгэх
init_db()

class handler(BaseHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Device-ID')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode('utf-8'))

    def get_auth_user(self):
        auth_header = self.headers.get('Authorization', '')
        device_id = self.headers.get('X-Device-ID', '')
        token = auth_header.split(' ', 1)[1].strip() if auth_header.startswith('Bearer ') else ''
        
        if not token:
            return None, "Нэвтрэх токен байхгүй байна"
            
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE current_session_token = ?", (token,))
        user = c.fetchone()
        
        if not user:
            conn.close()
            return None, "Сесс хүчингүй байна. Дахин нэвтэрнэ үү."
            
        if not user['is_active']:
            conn.close()
            return None, "Таны эрх хаагдсан байна."

        if not user['is_admin'] and device_id and user['current_device_id']:
            if user['current_device_id'] != device_id:
                conn.close()
                return None, "АНХААРУУЛГА: Таны хаяг өөр төхөөрөмж дээр ашиглагдаж байна!"
                
        c.execute("UPDATE users SET last_active_at = ? WHERE id = ?", (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user['id']))
        conn.commit()
        conn.close()
        return dict(user), None

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b'{}'
        try:
            payload = json.loads(body.decode('utf-8')) if body else {}
        except Exception:
            payload = {}

        if path.endswith("/login"):
            username = payload.get("username", "").strip()
            password = payload.get("password", "").strip()
            device_id = payload.get("device_id", "").strip()
            device_info = payload.get("device_info", "").strip() or self.headers.get('User-Agent', '')

            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = c.fetchone()

            if not user or user["password_hash"] != hash_pw(password):
                conn.close()
                return self.send_json({"error": "Хэрэглэгчийн нэр эсвэл нууц үг буруу байна."}, 401)

            new_token = secrets.token_hex(24)
            c.execute("""
            UPDATE users SET current_session_token = ?, current_device_id = ?, last_device_info = ?, last_active_at = ?
            WHERE id = ?
            """, (new_token, device_id, device_info[:200], datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user["id"]))
            conn.commit()
            conn.close()

            return self.send_json({
                "token": new_token,
                "user": {
                    "id": user["id"],
                    "username": user["username"],
                    "is_admin": bool(user["is_admin"]),
                    "expires_at": user["expires_at"]
                }
            })

        elif path.endswith("/pass-login"):
            pass_key = payload.get("pass_key", "").strip()
            device_id = payload.get("device_id", "").strip()
            device_info = payload.get("device_info", "").strip() or self.headers.get('User-Agent', '')

            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT * FROM access_passes WHERE pass_key = ?", (pass_key,))
            p = c.fetchone()

            if not p:
                conn.close()
                return self.send_json({"error": "Энэ линк олдсонгүй эсвэл хүчингүй байна."}, 404)

            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if not p["locked_device_id"]:
                exp_date = (datetime.now() + timedelta(days=p["days"])).strftime("%Y-%m-%d %H:%M:%S")
                c.execute("""
                UPDATE access_passes SET locked_device_id = ?, locked_device_info = ?, activated_at = ?, expires_at = ?
                WHERE id = ?
                """, (device_id, device_info[:200], now_str, exp_date, p["id"]))
                expires_at = exp_date
            else:
                if p["locked_device_id"] != device_id:
                    conn.close()
                    return self.send_json({
                        "error": "🔒 АНХААРУУЛГА: Энэ линк өөр төхөөрөмж дээр аль хэдийн түгжигдсэн байна! Бусад төхөөрөмжөөс нэвтрэх боломжгүй."
                    }, 403)
                expires_at = p["expires_at"]

            magic_username = f"pass_{pass_key[:8]}"
            new_token = secrets.token_hex(24)
            c.execute("SELECT id FROM users WHERE username = ?", (magic_username,))
            u = c.fetchone()
            if not u:
                c.execute("""
                INSERT INTO users (username, password_hash, name, is_admin, expires_at, current_session_token, current_device_id, last_device_info, last_active_at)
                VALUES (?, 'MAGIC_PASS', ?, 0, ?, ?, ?, ?, ?)
                """, (magic_username, p["note"] or "VIP Хэрэглэгч", expires_at, new_token, device_id, device_info[:200], now_str))
                uid = c.lastrowid
            else:
                uid = u["id"]
                c.execute("""
                UPDATE users SET current_session_token = ?, current_device_id = ?, last_device_info = ?, last_active_at = ?
                WHERE id = ?
                """, (new_token, device_id, device_info[:200], now_str, uid))

            conn.commit()
            conn.close()

            return self.send_json({
                "token": new_token,
                "user": {
                    "id": uid,
                    "username": magic_username,
                    "name": p["note"] or "VIP Хэрэглэгч",
                    "is_admin": False,
                    "expires_at": expires_at
                }
            })

        elif path.endswith("/admin/passes/create"):
            admin_user, err = self.get_auth_user()
            if err or not admin_user or not admin_user["is_admin"]:
                return self.send_json({"error": "Админ эрх шаардлагатай!"}, 403)

            note = payload.get("note", "").strip() or "VIP Хэрэглэгч"
            days = int(payload.get("days", 30))
            pass_key = secrets.token_urlsafe(16)

            conn = get_db()
            c = conn.cursor()
            c.execute("INSERT INTO access_passes (pass_key, note, days) VALUES (?, ?, ?)", (pass_key, note, days))
            conn.commit()
            conn.close()
            return self.send_json({"success": True, "pass_key": pass_key})

        elif path.endswith("/admin/passes/reset-device"):
            admin_user, err = self.get_auth_user()
            if err or not admin_user or not admin_user["is_admin"]:
                return self.send_json({"error": "Админ эрх шаардлагатай!"}, 403)

            pass_id = payload.get("pass_id")
            conn = get_db()
            c = conn.cursor()
            c.execute("UPDATE access_passes SET locked_device_id = NULL, locked_device_info = NULL WHERE id = ?", (pass_id,))
            conn.commit()
            conn.close()
            return self.send_json({"success": True})

        elif path.endswith("/admin/passes/toggle-active"):
            admin_user, err = self.get_auth_user()
            if err or not admin_user or not admin_user["is_admin"]:
                return self.send_json({"error": "Админ эрх шаардлагатай!"}, 403)

            pass_id = payload.get("pass_id")
            conn = get_db()
            c = conn.cursor()
            c.execute("UPDATE access_passes SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE id = ?", (pass_id,))
            conn.commit()
            conn.close()
            return self.send_json({"success": True})

        return self.send_json({"error": "Path not found"}, 404)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path

        if path.endswith("/me"):
            user, err = self.get_auth_user()
            if err:
                return self.send_json({"error": err}, 401)
            return self.send_json({"user": user})

        elif path.endswith("/movies"):
            user, err = self.get_auth_user()
            if err:
                return self.send_json({"error": err}, 401)
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT id, title, description, poster_url, duration, category FROM movies ORDER BY id DESC")
            movies = [dict(row) for row in c.fetchall()]
            conn.close()
            return self.send_json({"movies": movies})

        elif path.endswith("/movie-stream"):
            user, err = self.get_auth_user()
            if err:
                return self.send_json({"error": err}, 401)
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            movie_id = qs.get("id", [None])[0]
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT * FROM movies WHERE id = ?", (movie_id,))
            movie = c.fetchone()
            conn.close()
            if not movie:
                return self.send_json({"error": "Кино олдсонгүй"}, 404)
            return self.send_json({
                "movie": dict(movie),
                "watermark_text": f"{user['username']}"
            })

        elif path.endswith("/admin/passes"):
            admin_user, err = self.get_auth_user()
            if err or not admin_user or not admin_user["is_admin"]:
                return self.send_json({"error": "Админ эрх шаардлагатай!"}, 403)
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT * FROM access_passes ORDER BY id DESC")
            passes = [dict(row) for row in c.fetchall()]
            conn.close()
            return self.send_json({"passes": passes})

        return self.send_json({"error": "Path not found"}, 404)
