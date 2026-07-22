import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

# Impor fungsi-fungsi dari auth_system.py
from auth_system import register_user, login_user, compare_with_without_salt, load_db

PORT = 8000
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class WebAuthHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Mencegah logging default yang memenuhi output terminal
        pass

    def send_json_response(self, status_code, data):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def do_OPTIONS(self):
        # Dukungan CORS untuk kemudahan pengembangan/pengujian
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == '/' or path == '/index.html':
            html_file = os.path.join(DIRECTORY, 'index.html')
            if os.path.exists(html_file):
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                with open(html_file, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404, "File index.html tidak ditemukan")
        
        elif path == '/api/users':
            users = load_db()
            # Bersihkan hash/salt sensitif dari response jika diperlukan, tapi karena ini tugas kuliah/demo,
            # kita kirim lengkap agar user bisa melihat isi database JSON-nya.
            self.send_json_response(200, users)
        
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else ""

        try:
            body = json.loads(post_data) if post_data else {}
        except json.JSONDecodeError:
            self.send_json_response(400, {"status": "GAGAL", "alasan": "Format JSON tidak valid"})
            return

        if path == '/api/register':
            username = body.get('username', '').strip()
            password = body.get('password', '').strip()
            use_salt = body.get('use_salt', True)

            if not username or not password:
                self.send_json_response(400, {"status": "GAGAL", "alasan": "Username dan password wajib diisi"})
                return

            result = register_user(username, password, use_salt)
            self.send_json_response(200, result)

        elif path == '/api/login':
            username = body.get('username', '').strip()
            password = body.get('password', '').strip()

            if not username or not password:
                self.send_json_response(400, {"status": "GAGAL", "alasan": "Username dan password wajib diisi"})
                return

            result = login_user(username, password)
            self.send_json_response(200, result)

        elif path == '/api/compare':
            password = body.get('password', '').strip()

            if not password:
                self.send_json_response(400, {"status": "GAGAL", "alasan": "Password wajib diisi untuk demo"})
                return

            result = compare_with_without_salt(password)
            self.send_json_response(200, result)

        else:
            self.send_json_response(404, {"status": "GAGAL", "alasan": "Endpoint API tidak ditemukan"})

def run(server_class=HTTPServer, handler_class=WebAuthHandler, port=PORT):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"==========================================================================")
    print(f" Server berjalan di http://localhost:{port}")
    print(f" Silakan buka URL tersebut di browser Anda.")
    print(f" Tekan Ctrl+C untuk menghentikan server.")
    print(f"==========================================================================")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer dihentikan.")
        httpd.server_close()

if __name__ == '__main__':
    run()
