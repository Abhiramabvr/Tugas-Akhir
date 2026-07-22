# Dokumentasi Teknis — Sistem Autentikasi Hash Password SHA-256
Kelompok 1 — Tugas Besar Kriptografi

## 1. Arsitektur Sistem

```
┌─────────────────┐      ┌──────────────────────┐      ┌────────────────────┐
│   auth_system.py │─────▶│  users_db.json        │◀─────│   test_suite.py     │
│  (CLI + logika    │      │  (penyimpanan hash +  │      │  (16 skenario uji,  │
│   hashing/salt)   │      │   salt per user)       │      │   baca dataset_uji  │
└─────────┬─────────┘      └──────────────────────┘      │   .json)            │
          │                                                └────────────────────┘
          │
          ▼
┌───────────────────────┐
│ security_analysis.py   │
│ (benchmark waktu,       │
│  estimasi brute-force,  │
│  banding bcrypt/Argon2) │
└───────────────────────┘
```

## 2. Alur Proses (Flow)

### 2.1 Registrasi
```
Input: username, password
   │
   ▼
Cek username sudah ada di users_db.json?
   ├── Ya  → return GAGAL ("Username sudah terdaftar")
   └── Tidak
        │
        ▼
   Generate salt acak (secrets.token_hex)
        │
        ▼
   hash = SHA256(salt + password)
        │
        ▼
   Simpan {username: {salt, hash, use_salt, created_at}}
        │
        ▼
   return BERHASIL + salt + hash
```

### 2.2 Login
```
Input: username, password
   │
   ▼
Cek username ada di users_db.json?
   ├── Tidak → return GAGAL ("Username tidak ditemukan")
   └── Ya
        │
        ▼
   Ambil salt tersimpan milik username tsb
        │
        ▼
   hash_input = SHA256(salt + password_input)
        │
        ▼
   hash_input == hash_tersimpan ?
        ├── Ya  → return BERHASIL
        └── Tidak → return GAGAL ("Password salah")
```

## 3. Referensi Fungsi (`auth_system.py`)

| Fungsi | Parameter | Return | Deskripsi |
|---|---|---|---|
| `generate_salt(length=16)` | panjang byte | `str` (hex) | Membuat salt acak kriptografis via `secrets.token_hex` |
| `hash_password_sha256(password, salt="")` | password, salt | `str` (hex, 64 karakter) | Menghitung `SHA256(salt + password)` |
| `load_db()` / `save_db(db)` | - | `dict` | Baca/tulis `users_db.json` sebagai simulasi database |
| `register_user(username, password, use_salt=True)` | data user | `dict` status | Alur registrasi lengkap |
| `login_user(username, password)` | kredensial | `dict` status | Alur login + verifikasi hash |
| `compare_with_without_salt(password)` | password | `dict` perbandingan | Demo hash dengan vs tanpa salt untuk password yang sama |

## 4. Referensi Fungsi (`security_analysis.py`)

| Fungsi | Deskripsi |
|---|---|
| `benchmark_sha256(n_iter)` | Mengukur throughput hashing (hash/detik), dengan & tanpa salt |
| `analisis_brute_force(rate)` | Menghitung estimasi waktu brute-force untuk berbagai panjang/kompleksitas password, single-thread Python vs estimasi GPU |
| `perbandingan_algoritma()` | Membandingkan waktu hashing SHA-256 vs bcrypt (cost=12) vs Argon2id, beserta karakteristik keamanannya |

## 5. Format Data

### `users_db.json` (dibuat otomatis)
```json
{
  "andi123": {
    "salt": "b2f8981269c385136e511b18a54165c7",
    "hash": "0a7e3f9a1473b463a98129a89cd6c7fc...",
    "use_salt": true,
    "created_at": "2026-07-21T10:00:00"
  }
}
```

### `dataset_uji.json` (input pengujian, dibuat manual)
Berisi 10 data registrasi + 6 skenario kasus khusus (duplikat, login benar/salah, username tidak ada, perbandingan salt, konsistensi hash) — lihat file untuk struktur lengkap.

## 6. Kompleksitas & Kebutuhan Sistem
- Kompleksitas hashing SHA-256: O(1) terhadap panjang password (fixed block processing), tidak bergantung jumlah user.
- Kompleksitas pencarian user: O(1) rata-rata (dict lookup Python / key JSON).
- Tidak ada dependency eksternal wajib untuk `auth_system.py` dan `test_suite.py` (hanya modul standar Python: `hashlib`, `secrets`, `json`, `os`, `datetime`).
- `security_analysis.py` opsional membutuhkan `bcrypt` dan `argon2-cffi` (`pip install bcrypt argon2-cffi`) untuk bagian perbandingan algoritma; jika tidak tersedia, bagian tersebut otomatis dilewati tanpa error.

## 7. Batasan & Pengembangan Lanjutan
- SHA-256 murni tidak memiliki key-stretching, sehingga untuk implementasi production disarankan migrasi ke bcrypt/Argon2 (lihat `security_analysis_results.txt` bagian 3).
- Belum ada mekanisme rate-limiting / lockout terhadap percobaan login berulang.
- Penyimpanan menggunakan file JSON sebagai simulasi; pada sistem nyata sebaiknya menggunakan database dengan akses ter-enkripsi/ter-otorisasi.
