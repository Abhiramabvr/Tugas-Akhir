# Implementasi Hash Password SHA-256 — Kelompok 1
Studi Kasus: Pengamanan Sistem Pertukaran Dokumen Akademik Universitas ABC

## Struktur Folder yang Dirapikan
- **/app**: Berkas aplikasi utama
  - `auth_system.py` — Logika inti sistem autentikasi
  - `web_server.py` — Web Server HTTP berbasis Python
  - `index.html` — Antarmuka pengguna (Web UI)
  - `users_db.json` — Berkas basis data JSON simulasi pengguna
- **/tests**: Pengujian otomatis dan analisis keamanan
  - `test_suite.py` — Pengujian otomatis (16 skenario)
  - `security_analysis.py` — Script analisis keamanan lanjutan
  - `dataset_uji.json` — Kumpulan data pengujian
- **/docs**: Dokumentasi proyek dan laporan
  - `DOKUMENTASI_TEKNIS.md` — Penjelasan teknis sistem kriptografi
  - `Laporan_TB_Kriptografi_Kelompok1.docx` — Berkas laporan formal
  - `test_results.txt` — Log output pengujian otomatis
  - `security_analysis_results.txt` — Log output analisis keamanan

## Cara Menjalankan

### 1. Menjalankan Aplikasi Web (Web UI)
```bash
# Jalankan server web
python app/web_server.py
```
Setelah berjalan, buka browser dan akses: [http://localhost:8000](http://localhost:8000)

### 2. Menjalankan Pengujian Otomatis
```bash
# Jalankan unit testing otomatis
python tests/test_suite.py
```

### 3. Menjalankan Analisis Keamanan Lanjutan
```bash
# Jalankan script analisis performa & ketahanan brute-force
python tests/security_analysis.py
```

## Ringkasan Implementasi
1. **Hashing**: `hashlib.sha256()` dari library standar Python.
2. **Salt**: dibuat acak per user dengan `secrets.token_hex(16)` (kriptografis aman, bukan `random`).
3. **Skema hash**: `SHA256(salt + password)`. Salt disimpan bersama hash di `users_db.json`.
4. **Login**: password yang dimasukkan di-hash ulang dengan salt tersimpan, lalu dibandingkan dengan hash tersimpan.
5. **Mode perbandingan**: menunjukkan bahwa password sama tanpa salt selalu hasil hash sama (rawan rainbow table), sedangkan dengan salt hasilnya selalu berbeda tiap registrasi.
