# Implementasi Hash Password SHA-256 — Kelompok 1
Studi Kasus: Pengamanan Sistem Pertukaran Dokumen Akademik Universitas ABC

## Isi
- `auth_system.py` — aplikasi CLI utama (registrasi, login, demo salt, lihat user)
- `test_suite.py` — pengujian otomatis (16 skenario, 10+ dataset berbeda)
- `users_db.json` — "database" hasil registrasi (dibuat otomatis saat run)
- `test_results.txt` — hasil pengujian (dibuat otomatis saat run test_suite.py)

## Cara Menjalankan
```bash
# Jalankan aplikasi interaktif
python3 auth_system.py

# Jalankan pengujian otomatis (10+ data uji)
python3 test_suite.py
```
Tidak butuh library eksternal — hanya modul bawaan Python (`hashlib`, `secrets`, `json`).

## Ringkasan Implementasi
1. **Hashing**: `hashlib.sha256()` dari library standar Python.
2. **Salt**: dibuat acak per user dengan `secrets.token_hex(16)` (kriptografis aman, bukan `random`).
3. **Skema hash**: `SHA256(salt + password)`. Salt disimpan bersama hash di `users_db.json`.
4. **Login**: password yang dimasukkan di-hash ulang dengan salt tersimpan, lalu dibandingkan dengan hash tersimpan.
5. **Mode perbandingan**: menunjukkan bahwa password sama tanpa salt selalu hasil hash sama (rawan rainbow table), sedangkan dengan salt hasilnya selalu berbeda tiap registrasi.

## Hasil Pengujian
16 skenario dijalankan (registrasi 10 user berbeda, duplikat username, login sukses/gagal, username tak terdaftar, perbandingan salt, konsistensi hash) — seluruhnya **PASS (16/16, 100%)**. Detail lengkap ada di `test_results.txt`.

## Catatan Pengembangan Lanjutan (opsional)
- Bisa diganti ke bcrypt/Argon2 untuk key-stretching (SHA-256 murni tergolong cepat sehingga kurang tahan brute-force skala besar).
- Bisa tambah rate-limiting percobaan login.
