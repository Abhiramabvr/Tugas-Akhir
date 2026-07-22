"""
==========================================================================
 TUGAS BESAR KRIPTOGRAFI - KELOMPOK 1
 Script Pengujian Otomatis - Implementasi Hash Password SHA-256

 Menjalankan minimal 10 skenario pengujian dengan data berbeda,
 mencakup:
   - Registrasi berhasil
   - Registrasi gagal (username duplikat)
   - Login berhasil (password benar)
   - Login gagal (password salah)
   - Login gagal (username tidak ditemukan)
   - Perbandingan hash dengan & tanpa salt

 Hasil pengujian dicetak ke layar dan disimpan ke file test_results.txt
==========================================================================
"""

import os
import sys
import json

# Menambahkan folder 'app' ke PATH python agar bisa mengimpor auth_system
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app")))

from auth_system import (
    register_user,
    login_user,
    compare_with_without_salt,
    hash_password_sha256,
    DB_FILE,
)

RESULT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "test_results.txt")
DATASET_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dataset_uji.json")


def load_dataset() -> dict:
    """Memuat dataset uji dari file JSON eksternal (dataset_uji.json)."""
    with open(DATASET_FILE, "r") as f:
        return json.load(f)


def reset_db():
    """Menghapus database lama agar pengujian dimulai dari kondisi bersih."""
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)


def run_tests():
    reset_db()
    log_lines = []

    def log(text=""):
        print(text)
        log_lines.append(text)

    log("=" * 70)
    log("LAPORAN PENGUJIAN SISTEM AUTENTIKASI HASH PASSWORD SHA-256")
    log("=" * 70)

    # Dataset uji dimuat dari file eksternal dataset_uji.json
    dataset_json = load_dataset()
    dataset = [(d["username"], d["password"]) for d in dataset_json["dataset_registrasi"]]
    log(f"Dataset uji dimuat dari: {DATASET_FILE}")
    log(f"Jumlah data registrasi : {len(dataset)}")

    test_no = 1
    passed = 0
    total = 0

    # ---- 1-10: Registrasi dengan data berbeda ----
    for username, password in dataset:
        total += 1
        result = register_user(username, password, use_salt=True)
        status_ok = result["status"] == "BERHASIL"
        passed += status_ok
        log(f"\n[Test {test_no}] Registrasi user '{username}'")
        log(f"  Password asli : {password}")
        log(f"  Hasil         : {result['status']}")
        if status_ok:
            log(f"  Salt          : {result['salt']}")
            log(f"  Hash SHA-256  : {result['hash_password']}")
        log(f"  Verdict       : {'PASS' if status_ok else 'FAIL'}")
        test_no += 1

    # ---- 11: Registrasi gagal - username duplikat ----
    total += 1
    dup_username, dup_password = dataset[0]
    result = register_user(dup_username, "PasswordBaru!", use_salt=True)
    status_ok = result["status"] == "GAGAL"
    passed += status_ok
    log(f"\n[Test {test_no}] Registrasi duplikat username '{dup_username}' (harus GAGAL)")
    log(f"  Hasil   : {result}")
    log(f"  Verdict : {'PASS' if status_ok else 'FAIL'}")
    test_no += 1

    # ---- 12: Login berhasil - password benar ----
    total += 1
    username, password = dataset[0]
    result = login_user(username, password)
    status_ok = result["status"] == "BERHASIL"
    passed += status_ok
    log(f"\n[Test {test_no}] Login '{username}' dengan password BENAR")
    log(f"  Hasil   : {result}")
    log(f"  Verdict : {'PASS' if status_ok else 'FAIL'}")
    test_no += 1

    # ---- 13: Login gagal - password salah ----
    total += 1
    username, _ = dataset[1]
    result = login_user(username, "PasswordSalahBanget")
    status_ok = result["status"] == "GAGAL"
    passed += status_ok
    log(f"\n[Test {test_no}] Login '{username}' dengan password SALAH")
    log(f"  Hasil   : {result}")
    log(f"  Verdict : {'PASS' if status_ok else 'FAIL'}")
    test_no += 1

    # ---- 14: Login gagal - username tidak terdaftar ----
    total += 1
    result = login_user("user_tidak_ada", "sembarang")
    status_ok = result["status"] == "GAGAL"
    passed += status_ok
    log(f"\n[Test {test_no}] Login dengan username TIDAK TERDAFTAR")
    log(f"  Hasil   : {result}")
    log(f"  Verdict : {'PASS' if status_ok else 'FAIL'}")
    test_no += 1

    # ---- 15: Perbandingan hash dengan vs tanpa salt (password sama) ----
    total += 1
    demo_password = "PasswordSamaUntukDemo"
    result = compare_with_without_salt(demo_password)
    status_ok = (
        result["hash_dengan_salt (percobaan 1)"] != result["hash_dengan_salt (percobaan 2)"]
        and result["hash_dengan_salt (percobaan 1)"] != result["hash_tanpa_salt"]
    )
    passed += status_ok
    log(f"\n[Test {test_no}] Perbandingan hash DENGAN vs TANPA salt (password sama: '{demo_password}')")
    for k, v in result.items():
        log(f"  {k:35}: {v}")
    log(f"  Verdict : {'PASS - hash berbeda meski password sama' if status_ok else 'FAIL'}")
    test_no += 1

    # ---- 16: Konsistensi hash - password sama + salt sama harus hasil sama ----
    total += 1
    salt_tetap = "salt_tetap_untuk_test"
    h1 = hash_password_sha256("PasswordKonsisten", salt_tetap)
    h2 = hash_password_sha256("PasswordKonsisten", salt_tetap)
    status_ok = h1 == h2
    passed += status_ok
    log(f"\n[Test {test_no}] Konsistensi hash (password sama + salt sama -> hash harus sama)")
    log(f"  Hash 1  : {h1}")
    log(f"  Hash 2  : {h2}")
    log(f"  Verdict : {'PASS' if status_ok else 'FAIL'}")
    test_no += 1

    # ---- Ringkasan ----
    log("\n" + "=" * 70)
    log(f"RINGKASAN: {passed}/{total} pengujian PASS ({passed/total*100:.1f}%)")
    log("=" * 70)

    with open(RESULT_FILE, "w") as f:
        f.write("\n".join(log_lines))

    print(f"\nHasil lengkap tersimpan di: {RESULT_FILE}")


if __name__ == "__main__":
    run_tests()
