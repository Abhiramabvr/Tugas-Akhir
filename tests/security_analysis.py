"""
==========================================================================
 TUGAS BESAR KRIPTOGRAFI - KELOMPOK 1
 Analisis Keamanan Lanjutan - Implementasi Hash Password SHA-256

 Mencakup 3 aspek analisis:
   1. Analisis waktu eksekusi hashing (SHA-256 murni vs dengan salt)
   2. Estimasi ketahanan terhadap serangan brute-force / rainbow table
   3. Perbandingan SHA-256 vs algoritma khusus password (bcrypt, Argon2)

 Hasil dicetak ke layar dan disimpan ke security_analysis_results.txt
==========================================================================
"""

import time
import hashlib
import statistics
import os
import sys

# Menambahkan folder 'app' ke PATH python agar bisa mengimpor auth_system
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app")))

from auth_system import hash_password_sha256, generate_salt

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

try:
    from argon2 import PasswordHasher
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


RESULT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "security_analysis_results.txt")
log_lines = []


def log(text=""):
    print(text)
    log_lines.append(text)


# --------------------------------------------------------------------
# 1. ANALISIS WAKTU EKSEKUSI (SPEED BENCHMARK)
# --------------------------------------------------------------------

def benchmark_sha256(n_iter: int = 100_000):
    log("\n" + "=" * 70)
    log("1. ANALISIS WAKTU EKSEKUSI HASHING")
    log("=" * 70)

    password = "ContohPassword123!"
    salt = generate_salt()

    # SHA-256 tanpa salt, satu kali hash per iterasi
    start = time.perf_counter()
    for _ in range(n_iter):
        hash_password_sha256(password, "")
    elapsed_no_salt = time.perf_counter() - start

    # SHA-256 dengan salt
    start = time.perf_counter()
    for _ in range(n_iter):
        hash_password_sha256(password, salt)
    elapsed_with_salt = time.perf_counter() - start

    rate_no_salt = n_iter / elapsed_no_salt
    rate_with_salt = n_iter / elapsed_with_salt

    log(f"Jumlah iterasi uji        : {n_iter:,}")
    log(f"Waktu total (tanpa salt)  : {elapsed_no_salt:.4f} detik")
    log(f"Waktu total (dengan salt) : {elapsed_with_salt:.4f} detik")
    log(f"Throughput (tanpa salt)   : {rate_no_salt:,.0f} hash/detik")
    log(f"Throughput (dengan salt)  : {rate_with_salt:,.0f} hash/detik")
    log("Kesimpulan: Penambahan salt TIDAK menambah beban komputasi secara")
    log("signifikan (hanya operasi penggabungan string), namun secara drastis")
    log("meningkatkan keamanan karena setiap hash menjadi unik per user.")

    return rate_no_salt


# --------------------------------------------------------------------
# 2. ESTIMASI KETAHANAN BRUTE-FORCE
# --------------------------------------------------------------------

def analisis_brute_force(hash_rate_per_second: float):
    log("\n" + "=" * 70)
    log("2. ESTIMASI KETAHANAN TERHADAP SERANGAN BRUTE-FORCE")
    log("=" * 70)

    log(f"Asumsi kecepatan hashing SHA-256 (single-thread, Python): "
        f"~{hash_rate_per_second:,.0f} hash/detik")
    log("Catatan: GPU modern dapat mencapai >10 miliar hash SHA-256/detik,")
    log("jauh lebih cepat dari implementasi Python murni di atas.")

    # Skenario ruang password (charset campuran huruf besar/kecil/angka/simbol)
    skenario = [
        ("PIN 4 digit (angka saja)", 10 ** 4),
        ("Password 6 karakter (lowercase)", 26 ** 6),
        ("Password 8 karakter (alfanumerik)", 62 ** 8),
        ("Password 8 karakter (alfanumerik + simbol)", 94 ** 8),
        ("Password 12 karakter (alfanumerik + simbol)", 94 ** 12),
    ]

    gpu_rate = 10_000_000_000  # 10 miliar hash/detik, estimasi GPU modern untuk SHA-256 murni

    log(f"\n{'Skenario Password':45}{'Waktu (Python, single-thread)':35}{'Waktu (estimasi GPU)'}")
    log("-" * 110)
    for nama, ruang in skenario:
        waktu_python = ruang / hash_rate_per_second
        waktu_gpu = ruang / gpu_rate
        log(f"{nama:45}{format_waktu(waktu_python):35}{format_waktu(waktu_gpu)}")

    log("\nKesimpulan:")
    log("- SHA-256 murni TIDAK cocok untuk hashing password tanpa key-stretching")
    log("  karena kecepatannya yang tinggi justru memudahkan brute-force pada")
    log("  password pendek atau lemah (lihat kolom 'estimasi GPU').")
    log("- Salt TIDAK memperlambat brute-force per password (waktu hash tetap sama),")
    log("  namun salt MENCEGAH serangan precomputed rainbow table dan memaksa")
    log("  penyerang melakukan brute-force ULANG untuk setiap akun (tidak bisa")
    log("  reuse tabel hash yang sama untuk banyak akun sekaligus).")
    log("- Untuk keamanan production-grade, disarankan algoritma dengan")
    log("  key-stretching seperti bcrypt/Argon2 (lihat bagian 3).")


def format_waktu(detik: float) -> str:
    if detik < 1:
        return f"{detik*1000:.2f} milidetik"
    elif detik < 60:
        return f"{detik:.2f} detik"
    elif detik < 3600:
        return f"{detik/60:.2f} menit"
    elif detik < 86400:
        return f"{detik/3600:.2f} jam"
    elif detik < 31536000:
        return f"{detik/86400:.2f} hari"
    else:
        tahun = detik / 31536000
        if tahun > 1e9:
            return f"{tahun:.2e} tahun"
        return f"{tahun:,.0f} tahun"


# --------------------------------------------------------------------
# 3. PERBANDINGAN SHA-256 vs BCRYPT vs ARGON2
# --------------------------------------------------------------------

def perbandingan_algoritma():
    log("\n" + "=" * 70)
    log("3. PERBANDINGAN SHA-256 (+ SALT) vs BCRYPT vs ARGON2")
    log("=" * 70)

    password = "ContohPassword123!"
    n_iter = 20  # bcrypt & argon2 sengaja lambat, jadi iterasi kecil

    # --- SHA-256 + salt ---
    salt = generate_salt()
    start = time.perf_counter()
    for _ in range(n_iter):
        hash_password_sha256(password, salt)
    t_sha256 = (time.perf_counter() - start) / n_iter

    log(f"\nSHA-256 + salt   : {t_sha256*1000:.4f} ms/hash "
        f"({1/t_sha256:,.0f} hash/detik) -> CEPAT, rentan brute-force skala besar")

    # --- bcrypt ---
    if BCRYPT_AVAILABLE:
        start = time.perf_counter()
        for _ in range(n_iter):
            bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
        t_bcrypt = (time.perf_counter() - start) / n_iter
        log(f"bcrypt (cost=12) : {t_bcrypt*1000:.4f} ms/hash "
            f"({1/t_bcrypt:,.1f} hash/detik) -> LAMBAT by design, tahan brute-force")
    else:
        log("bcrypt tidak tersedia di lingkungan ini.")

    # --- Argon2 ---
    if ARGON2_AVAILABLE:
        ph = PasswordHasher()
        start = time.perf_counter()
        for _ in range(n_iter):
            ph.hash(password)
        t_argon2 = (time.perf_counter() - start) / n_iter
        log(f"Argon2id (default): {t_argon2*1000:.4f} ms/hash "
            f"({1/t_argon2:,.1f} hash/detik) -> LAMBAT + boros memori, paling tahan")
    else:
        log("Argon2 tidak tersedia di lingkungan ini.")

    log("\nTabel Ringkasan Karakteristik:")
    log(f"{'Algoritma':15}{'Key-stretching':18}{'Butuh Memori Besar':22}{'Rekomendasi'}")
    log("-" * 85)
    log(f"{'SHA-256':15}{'Tidak':18}{'Tidak':22}{'Checksum/integritas data, BUKAN password'}")
    log(f"{'bcrypt':15}{'Ya (cost factor)':18}{'Kecil (4KB)':22}{'Layak untuk hashing password'}")
    log(f"{'Argon2':15}{'Ya (time+memory)':18}{'Besar (dapat diatur)':22}{'Terbaik saat ini (rekomendasi OWASP)'}")

    log("\nKesimpulan Akhir:")
    log("SHA-256 dipilih pada tugas ini karena kesederhanaan dan tujuan")
    log("pembelajaran konsep hashing & salting. Untuk implementasi production")
    log("pada sistem akademik yang sesungguhnya, algoritma seperti Argon2id")
    log("atau bcrypt lebih direkomendasikan karena dirancang khusus untuk")
    log("memperlambat serangan brute-force (key-stretching), sesuai rekomendasi")
    log("OWASP Password Storage Cheat Sheet.")


def run_security_analysis():
    log("=" * 70)
    log("LAPORAN ANALISIS KEAMANAN LANJUTAN")
    log("Implementasi Hash Password SHA-256 - Kelompok 1")
    log("=" * 70)

    rate = benchmark_sha256()
    analisis_brute_force(rate)
    perbandingan_algoritma()

    with open(RESULT_FILE, "w") as f:
        f.write("\n".join(log_lines))

    print(f"\nHasil lengkap tersimpan di: {RESULT_FILE}")


if __name__ == "__main__":
    run_security_analysis()
