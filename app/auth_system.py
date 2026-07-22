"""
==========================================================================
 TUGAS BESAR KRIPTOGRAFI - KELOMPOK 1
 Modul: Implementasi Hash Password Menggunakan SHA-256
 Studi Kasus: Pengamanan Sistem Pertukaran Dokumen Akademik Universitas

 Deskripsi:
   Sistem autentikasi sederhana berbasis CLI yang menerapkan hashing
   password menggunakan algoritma SHA-256, dilengkapi dengan mekanisme
   salt untuk meningkatkan keamanan terhadap serangan rainbow table.

 Fitur:
   1. Registrasi pengguna (password di-hash dengan SHA-256 + salt)
   2. Login (verifikasi hash ulang)
   3. Mode perbandingan hash DENGAN salt vs TANPA salt
   4. Penyimpanan data pengguna ke file JSON (users_db.json)
==========================================================================
"""

import hashlib
import secrets
import json
import os
from datetime import datetime

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users_db.json")


# --------------------------------------------------------------------
# FUNGSI-FUNGSI INTI KRIPTOGRAFI
# --------------------------------------------------------------------

def generate_salt(length: int = 16) -> str:
    """Menghasilkan salt acak dalam bentuk hex string."""
    return secrets.token_hex(length)


def hash_password_sha256(password: str, salt: str = "") -> str:
    """
    Menghitung hash SHA-256 dari password.
    Jika salt diberikan, salt digabungkan (concat) di depan password
    sebelum di-hash: hash(salt + password)
    """
    data = (salt + password).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------
# PENYIMPANAN DATA (JSON sebagai simulasi database)
# --------------------------------------------------------------------

def load_db() -> dict:
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def save_db(db: dict) -> None:
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=4)


# --------------------------------------------------------------------
# FUNGSI UTAMA SISTEM (dapat dipanggil dari CLI maupun test suite)
# --------------------------------------------------------------------

def register_user(username: str, password: str, use_salt: bool = True) -> dict:
    """
    Registrasi pengguna baru.
    Mengembalikan dict berisi status dan detail hasil hashing.
    """
    db = load_db()

    if username in db:
        return {"status": "GAGAL", "alasan": "Username sudah terdaftar"}

    salt = generate_salt() if use_salt else ""
    hashed = hash_password_sha256(password, salt)

    db[username] = {
        "salt": salt,
        "hash": hashed,
        "use_salt": use_salt,
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }
    save_db(db)

    return {
        "status": "BERHASIL",
        "username": username,
        "salt": salt if use_salt else "(tidak digunakan)",
        "hash_password": hashed,
    }


def login_user(username: str, password: str) -> dict:
    """
    Login pengguna: hash ulang password yang dimasukkan lalu
    bandingkan dengan hash yang tersimpan di database.
    """
    db = load_db()

    if username not in db:
        return {"status": "GAGAL", "alasan": "Username tidak ditemukan"}

    record = db[username]
    salt = record["salt"]
    hashed_input = hash_password_sha256(password, salt)

    if hashed_input == record["hash"]:
        return {"status": "BERHASIL", "username": username}
    else:
        return {"status": "GAGAL", "alasan": "Password salah"}


def compare_with_without_salt(password: str) -> dict:
    """
    Mendemonstrasikan perbedaan hash SHA-256 untuk password yang SAMA,
    dengan dan tanpa salt. Berguna untuk menunjukkan bahwa salt membuat
    hash unik meski passwordnya identik (mencegah rainbow table attack).
    """
    salt1 = generate_salt()
    salt2 = generate_salt()

    hash_no_salt = hash_password_sha256(password, "")
    hash_with_salt_1 = hash_password_sha256(password, salt1)
    hash_with_salt_2 = hash_password_sha256(password, salt2)

    return {
        "password": password,
        "hash_tanpa_salt": hash_no_salt,
        "hash_dengan_salt (percobaan 1)": hash_with_salt_1,
        "hash_dengan_salt (percobaan 2)": hash_with_salt_2,
        "catatan": (
            "Tanpa salt, password yang sama SELALU menghasilkan hash yang "
            "sama (rentan rainbow table). Dengan salt, setiap registrasi "
            "menghasilkan hash BERBEDA walau password identik."
        ),
    }


# --------------------------------------------------------------------
# TAMPILAN CLI (ANTARMUKA PENGGUNA)
# --------------------------------------------------------------------

def print_header(title: str):
    print("\n" + "=" * 60)
    print(f" {title}")
    print("=" * 60)


def menu_register():
    print_header("REGISTRASI PENGGUNA BARU")
    username = input("Masukkan username : ").strip()
    password = input("Masukkan password : ").strip()

    use_salt_input = input("Gunakan salt? (y/n) [default y]: ").strip().lower()
    use_salt = use_salt_input != "n"

    result = register_user(username, password, use_salt)

    print("\n--- HASIL REGISTRASI ---")
    for k, v in result.items():
        print(f"{k:15}: {v}")


def menu_login():
    print_header("LOGIN PENGGUNA")
    username = input("Masukkan username : ").strip()
    password = input("Masukkan password : ").strip()

    result = login_user(username, password)

    print("\n--- HASIL LOGIN ---")
    for k, v in result.items():
        print(f"{k:15}: {v}")


def menu_compare():
    print_header("PERBANDINGAN HASH DENGAN vs TANPA SALT")
    password = input("Masukkan password untuk didemonstrasikan: ").strip()
    result = compare_with_without_salt(password)

    print("\n--- HASIL PERBANDINGAN ---")
    for k, v in result.items():
        print(f"{k:35}: {v}")


def menu_list_users():
    print_header("DAFTAR PENGGUNA TERSIMPAN")
    db = load_db()
    if not db:
        print("Belum ada pengguna terdaftar.")
        return
    for username, data in db.items():
        print(f"- {username} | salt={'ya' if data['use_salt'] else 'tidak'} "
              f"| hash={data['hash'][:20]}... | dibuat={data['created_at']}")


def main_menu():
    while True:
        print_header("SISTEM AUTENTIKASI HASH PASSWORD SHA-256")
        print("1. Registrasi Pengguna")
        print("2. Login")
        print("3. Demo Perbandingan Hash (dengan vs tanpa salt)")
        print("4. Lihat Daftar Pengguna Tersimpan")
        print("5. Keluar")
        pilihan = input("Pilih menu (1-5): ").strip()

        if pilihan == "1":
            menu_register()
        elif pilihan == "2":
            menu_login()
        elif pilihan == "3":
            menu_compare()
        elif pilihan == "4":
            menu_list_users()
        elif pilihan == "5":
            print("Terima kasih. Program selesai.")
            break
        else:
            print("Pilihan tidak valid, coba lagi.")


if __name__ == "__main__":
    main_menu()
