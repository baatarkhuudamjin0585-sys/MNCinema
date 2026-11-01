import http.server
import json
import os
import sys
import hashlib
import secrets
from datetime import datetime, timedelta
import urllib.parse
from database import get_db, init_db

PORT = 8080

def hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode('utf-8')).hexdigest()

class MovieServerHandler(http.server.SimpleHTTPRequestHandler):
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
        
        token = ''
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ', 1)[1].strip()
        
        if not token:
            return None, "Нэвтрэх токен байхгүй байна"
            
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE current_session_token = ?", (token,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return None, "Сесс хүчингүй байна. Дахин нэвтэрнэ үү."
            
        if not user['is_active']:
            conn.close()
            return None, "Таны эрх хаагдсан байна."
            
        if user['expires_at']:
            try:
                exp = datetime.strptime(user['expires_at'], "%Y-%m-%d %H:%M:%S")
                if datetime.now() > exp:
                    conn.close()
                    return None, "Таны үзэх хугацаа дууссан байна. Төлбөрөө сунгана уу."
            except Exception:
                pass

        # Нэг төхөөрөмжийн шалгалт (Админаас бусад хэрэглэгчид)
        if not user['is_admin'] and device_id and user['current_device_id']:
            if user['current_device_id'] != device_id:
                conn.close()
                return None, "АНХААРУУЛГА: Таны хаяг өөр төхөөрөмжөөс нэвтэрсэн байна! Нэг зэрэг олон төхөөрөмжөөс үзэх боломжгүй."
                
        # Сүүлийн идэвхтэй цагийг шинэчлэх
        cursor.execute("UPDATE users SET last_active_at = ? WHERE id = ?", (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user['id']))
        conn.commit()
        conn.close()
        return dict(user), None

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b'{}'
        try:
            payload = json.loads(body.decode('utf-8')) if body else {}
        except Exception:
            payload = {}

        # 1.1 MAGIC PASS АШИГЛАН НЭВТРЭХ (/api/pass-login)
        if path == "/api/pass-login":
            pass_key = payload.get("pass_key", "").strip()
            device_id = payload.get("device_id", "").strip()
            device_info = payload.get("device_info", "").strip() or self.headers.get('User-Agent', '')

            if not pass_key:
                return self.send_json({"error": "Pass key байхгүй байна."}, 400)

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM access_passes WHERE pass_key = ?", (pass_key,))
            p = cursor.fetchone()

            if not p:
                conn.close()
                return self.send_json({"error": "Энэ линк олдсонгүй эсвэл хүчингүй байна."}, 404)

            if not p["is_active"]:
                conn.close()
                return self.send_json({"error": "Энэ линкийн эрхийг админаас хаасан байна."}, 403)

            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # ТӨХӨӨРӨМЖ БАРЬЦАЛДУУЛАХ / ТҮГЖИХ ЛОГИК:
            if not p["locked_device_id"]:
                # Анх удаа энэ төхөөрөмж дээр нээгдэж байна -> Түгжинэ
                exp_date = (datetime.now() + timedelta(days=p["days"])).strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute("""
                UPDATE access_passes SET 
                    locked_device_id = ?,
                    locked_device_info = ?,
                    activated_at = ?,
                    expires_at = ?
                WHERE id = ?
                """, (device_id, device_info[:200], now_str, exp_date, p["id"]))
                expires_at = exp_date
            else:
                # Өмнө нь аль хэдийн өөр төхөөрөмж дээр нээгдсэн байна
                if p["locked_device_id"] != device_id:
                    conn.close()
                    return self.send_json({
                        "error": "🔒 АНХААРУУЛГА: Энэ линк анх нээгдсэн өөр төхөөрөмж дээр аль хэдийн түгжигдсэн байна! Бусад төхөөрөмж дээр ашиглах боломжгүй."
                    }, 403)
                
                # Хугацаа шалгах
                if p["expires_at"]:
                    try:
                        exp = datetime.strptime(p["expires_at"], "%Y-%m-%d %H:%M:%S")
                        if datetime.now() > exp:
                            conn.close()
                            return self.send_json({"error": "Энэ линкийн үзэх хугацаа дууссан байна."}, 403)
                    except Exception:
                        pass
                expires_at = p["expires_at"]

            # Хэрэглэгчтэй ижил сесс токен үүсгэж хэрэглэгчийн баазад бүртгэх
            magic_username = f"pass_{pass_key[:8]}"
            new_session_token = secrets.token_hex(24)
            
            cursor.execute("SELECT id FROM users WHERE username = ?", (magic_username,))
            u = cursor.fetchone()
            if not u:
                cursor.execute("""
                INSERT INTO users (username, password_hash, name, is_admin, expires_at, current_session_token, current_device_id, last_device_info, last_active_at)
                VALUES (?, 'MAGIC_PASS', ?, 0, ?, ?, ?, ?, ?)
                """, (magic_username, p["note"] or "VIP Хэрэглэгч", expires_at, new_session_token, device_id, device_info[:200], now_str))
                uid = cursor.lastrowid
            else:
                uid = u["id"]
                cursor.execute("""
                UPDATE users SET 
                    current_session_token = ?,
                    current_device_id = ?,
                    last_device_info = ?,
                    last_active_at = ?,
                    expires_at = ?
                WHERE id = ?
                """, (new_session_token, device_id, device_info[:200], now_str, expires_at, uid))

            conn.commit()
            conn.close()

            return self.send_json({
                "token": new_session_token,
                "user": {
                    "id": uid,
                    "username": magic_username,
                    "name": p["note"] or "VIP Хэрэглэгч",
                    "is_admin": False,
                    "expires_at": expires_at
                }
            })

        # 1.2 АДМИН: ШИНЭ УХААЛАГ ЛИНК ҮҮСГЭХ (/api/admin/passes/create)
        elif path == "/api/admin/passes/create":
            admin_user, err = self.get_auth_user()
            if err or not admin_user or not admin_user["is_admin"]:
                return self.send_json({"error": "Админ эрх шаардлагатай!"}, 403)

            note = payload.get("note", "").strip() or "VIP Хэрэглэгч"
            days = int(payload.get("days", 30))
            pass_key = secrets.token_urlsafe(16)

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO access_passes (pass_key, note, days)
            VALUES (?, ?, ?)
            """, (pass_key, note, days))
            conn.commit()
            conn.close()

            return self.send_json({
                "success": True,
                "pass_key": pass_key,
                "message": "Ухаалаг линк амжилттай үүслээ!"
            })

        # 1.3 АДМИН: ЛИНКИЙН ТӨХӨӨРӨМЖ САЛГАХ (/api/admin/passes/reset-device)
        elif path == "/api/admin/passes/reset-device":
            admin_user, err = self.get_auth_user()
            if err or not admin_user or not admin_user["is_admin"]:
                return self.send_json({"error": "Админ эрх шаардлагатай!"}, 403)

            pass_id = payload.get("pass_id")
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE access_passes SET locked_device_id = NULL, locked_device_info = NULL
            WHERE id = ?
            """, (pass_id,))
            conn.commit()
            conn.close()
            return self.send_json({"success": True, "message": "Төхөөрөмж салгагдлаа. Дахин шинэ төхөөрөмж дээр нээх боломжтой."})

        # 1.4 АДМИН: ЛИНКИЙН ТӨЛӨВ ӨӨРЧЛӨХ (/api/admin/passes/toggle-active)
        elif path == "/api/admin/passes/toggle-active":
            admin_user, err = self.get_auth_user()
            if err or not admin_user or not admin_user["is_admin"]:
                return self.send_json({"error": "Админ эрх шаардлагатай!"}, 403)

            pass_id = payload.get("pass_id")
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("UPDATE access_passes SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE id = ?", (pass_id,))
            conn.commit()
            conn.close()
            return self.send_json({"success": True})

        # 1. НЭВТРЭХ API (/api/login)
        if path == "/api/login":
            username = payload.get("username", "").strip()
            password = payload.get("password", "").strip()
            device_id = payload.get("device_id", "").strip()
            device_info = payload.get("device_info", "").strip() or self.headers.get('User-Agent', '')

            if not username or not password:
                return self.send_json({"error": "Хэрэглэгчийн нэр, нууц үгээ оруулна уу."}, 400)

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

            if not user or user["password_hash"] != hash_pw(password):
                conn.close()
                return self.send_json({"error": "Хэрэглэгчийн нэр эсвэл нууц үг буруу байна."}, 401)

            if not user["is_active"]:
                conn.close()
                return self.send_json({"error": "Энэ хэрэглэгчийн эрх хаагдсан байна."}, 403)

            # Төлбөрийн хугацаа шалгах
            if user["expires_at"]:
                try:
                    exp = datetime.strptime(user["expires_at"], "%Y-%m-%d %H:%M:%S")
                    if datetime.now() > exp:
                        conn.close()
                        return self.send_json({"error": "Таны үзэх эрхийн хугацаа дууссан байна."}, 403)
                except Exception:
                    pass

            # НЭГ ТӨХӨӨРӨМЖИЙН БОДЛОГО:
            # Шинээр нэвтрэхэд шинэ сесс токен олгож, хуучин төхөөрөмжийг шууд хүчингүй болгоно!
            new_session_token = secrets.token_hex(24)
            cursor.execute("""
            UPDATE users SET 
                current_session_token = ?,
                current_device_id = ?,
                last_device_info = ?,
                last_active_at = ?
            WHERE id = ?
            """, (new_session_token, device_id, device_info[:200], datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user["id"]))
            
            # Лог бүртгэх
            cursor.execute("""
            INSERT INTO activity_logs (user_id, action, device_info, ip_address)
            VALUES (?, 'LOGIN', ?, ?)
            """, (user["id"], device_info[:150], self.client_address[0]))

            conn.commit()
            conn.close()

            return self.send_json({
                "token": new_session_token,
                "user": {
                    "id": user["id"],
                    "username": user["username"],
                    "name": user["name"],
                    "is_admin": bool(user["is_admin"]),
                    "expires_at": user["expires_at"]
                }
            })

        # 2. АДМИН: ХЭРЭГЛЭГЧ НЭМЭХ (/api/admin/users/create)
        elif path == "/api/admin/users/create":
            admin_user, err = self.get_auth_user()
            if err or not admin_user or not admin_user["is_admin"]:
                return self.send_json({"error": "Админ эрх шаардлагатай!"}, 403)

            username = payload.get("username", "").strip()
            password = payload.get("password", "").strip()
            name = payload.get("name", "").strip()
            phone = payload.get("phone", "").strip()
            days = int(payload.get("days", 30))

            if not username or not password:
                return self.send_json({"error": "Нэвтрэх нэр, нууц үг заавал байх ёстой!"}, 400)

            expires_at = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")

            conn = get_db()
            cursor = conn.cursor()
            try:
                cursor.execute("""
                INSERT INTO users (username, password_hash, name, phone, expires_at)
                VALUES (?, ?, ?, ?, ?)
                """, (username, hash_pw(password), name, phone, expires_at))
                conn.commit()
                conn.close()
                return self.send_json({"success": True, "message": f"{username} амжилттай үүслээ! Хугацаа: {days} хоног"})
            except sqlite3.IntegrityError:
                conn.close()
                return self.send_json({"error": "Ийм хэрэглэгчийн нэр аль хэдийн бүртгэгдсэн байна!"}, 400)

        # 3. АДМИН: ТӨХӨӨРӨМЖ САЛГАХ / RESET DEVICE (/api/admin/users/reset-device)
        elif path == "/api/admin/users/reset-device":
            admin_user, err = self.get_auth_user()
            if err or not admin_user or not admin_user["is_admin"]:
                return self.send_json({"error": "Админ эрх шаардлагатай!"}, 403)

            target_user_id = payload.get("user_id")
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE users SET current_session_token = NULL, current_device_id = NULL
            WHERE id = ?
            """, (target_user_id,))
            conn.commit()
            conn.close()
            return self.send_json({"success": True, "message": "Төхөөрөмж амжилттай салгагдлаа."})

        # 4. АДМИН: ХЭРЭГЛЭГЧИЙН ТӨЛӨВ ӨӨРЧЛӨХ (Идэвхжүүлэх / Хаах)
        elif path == "/api/admin/users/toggle-active":
            admin_user, err = self.get_auth_user()
            if err or not admin_user or not admin_user["is_admin"]:
                return self.send_json({"error": "Админ эрх шаардлагатай!"}, 403)

            target_user_id = payload.get("user_id")
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE id = ?", (target_user_id,))
            conn.commit()
            conn.close()
            return self.send_json({"success": True})

        # 5. АДМИН: ШИНЭ КИНО НЭМЭХ (/api/admin/movies/create)
        elif path == "/api/admin/movies/create":
            admin_user, err = self.get_auth_user()
            if err or not admin_user or not admin_user["is_admin"]:
                return self.send_json({"error": "Админ эрх шаардлагатай!"}, 403)

            title = payload.get("title", "").strip()
            desc = payload.get("description", "").strip()
            poster_url = payload.get("poster_url", "").strip()
            video_url = payload.get("video_url", "").strip()
            duration = payload.get("duration", "").strip()

            if not title or not video_url:
                return self.send_json({"error": "Киноны нэр болон видеоны холбоос заавал хэрэгтэй!"}, 400)

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO movies (title, description, poster_url, video_url, duration)
            VALUES (?, ?, ?, ?, ?)
            """, (title, desc, poster_url, video_url, duration))
            conn.commit()
            conn.close()
            return self.send_json({"success": True, "message": "Кино амжилттай нэмэгдлээ!"})

        else:
            return self.send_json({"error": "Path not found"}, 404)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # API: Хэрэглэгчийн мэдээлэл шалгах (/api/me)
        if path == "/api/me":
            user, err = self.get_auth_user()
            if err:
                return self.send_json({"error": err}, 401)
            return self.send_json({"user": user})

        # API: Кинонуудын жагсаалт (/api/movies)
        elif path == "/api/movies":
            user, err = self.get_auth_user()
            if err:
                return self.send_json({"error": err}, 401)
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT id, title, description, poster_url, duration, category, created_at FROM movies ORDER BY id DESC")
            movies = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return self.send_json({"movies": movies})

        # API: Тодорхой киноны дэлгэрэнгүй ба Video Stream URL (/api/movie-stream)
        elif path == "/api/movie-stream":
            user, err = self.get_auth_user()
            if err:
                return self.send_json({"error": err}, 401)
            qs = urllib.parse.parse_qs(parsed.query)
            movie_id = qs.get("id", [None])[0]
            if not movie_id:
                return self.send_json({"error": "Кино ID байхгүй байна"}, 400)

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM movies WHERE id = ?", (movie_id,))
            movie = cursor.fetchone()
            conn.close()
            if not movie:
                return self.send_json({"error": "Кино олдсонгүй"}, 404)

            return self.send_json({
                "movie": dict(movie),
                "watermark_text": f"{user['username']} | {user['phone'] or ''}"
            })

        # API: АДМИН: Бүх Ухаалаг Линкүүдийг (Passes) харах (/api/admin/passes)
        elif path == "/api/admin/passes":
            admin_user, err = self.get_auth_user()
            if err or not admin_user or not admin_user["is_admin"]:
                return self.send_json({"error": "Админ эрх шаардлагатай!"}, 403)

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("""
            SELECT id, pass_key, note, days, locked_device_id, locked_device_info,
                   activated_at, expires_at, is_active, created_at
            FROM access_passes ORDER BY id DESC
            """)
            passes = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return self.send_json({"passes": passes})

        # API: АДМИН: Бүх хэрэглэгчид ба тэдний төхөөрөмжүүдийг харах (/api/admin/users)
        elif path == "/api/admin/users":
            admin_user, err = self.get_auth_user()
            if err or not admin_user or not admin_user["is_admin"]:
                return self.send_json({"error": "Админ эрх шаардлагатай!"}, 403)

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("""
            SELECT id, username, name, phone, is_admin, is_active, expires_at,
                   current_device_id, last_device_info, last_active_at, created_at
            FROM users ORDER BY id DESC
            """)
            users = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return self.send_json({"users": users})

        # Статик HTML файлууд үйлчлэх
        else:
            static_dir = os.path.join(os.path.dirname(__file__), "public")
            if path == "/" or path == "":
                filepath = os.path.join(static_dir, "index.html")
            else:
                rel = path.lstrip("/")
                filepath = os.path.join(static_dir, rel)

            if os.path.isfile(filepath):
                self.send_response(200)
                if filepath.endswith(".html"):
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                elif filepath.endswith(".css"):
                    self.send_header("Content-Type", "text/css; charset=utf-8")
                elif filepath.endswith(".js"):
                    self.send_header("Content-Type", "application/javascript; charset=utf-8")
                elif filepath.endswith(".mp4"):
                    self.send_header("Content-Type", "video/mp4")
                self.end_headers()
                with open(filepath, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_json({"error": "Not Found"}, 404)

def ensure_admin():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE is_admin = 1")
    admin = cursor.fetchone()
    if not admin:
        cursor.execute("""
        INSERT INTO users (username, password_hash, name, is_admin, is_active)
        VALUES ('admin', ?, 'Администратор', 1, 1)
        """, (hash_pw("admin123"),))
        conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    ensure_admin()
    server = http.server.ThreadingHTTPServer(('0.0.0.0', PORT), MovieServerHandler)
    print(f"Movie Platform backend running on http://localhost:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
