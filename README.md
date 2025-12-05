# Proyek: AI-Powered Web Security Scanner

Selamat datang di Proyek AI-Powered Web Security Scanner! Proyek ini bertujuan untuk mengidentifikasi potensi kerentanan keamanan pada aplikasi web menggunakan pendekatan yang diperkuat oleh kecerdasan buatan.

## Deskripsi Proyek

Alat ini menggabungkan teknik crawling web tradisional dengan analisis kerentanan bertenaga AI untuk mendeteksi potensi SQL Injection dan Cross-Site Scripting (XSS). Ini dirancang untuk membantu pengembang dan profesional keamanan dalam mengidentifikasi kelemahan dalam aplikasi web mereka.

### Fitur Utama:

*   **Intelligent Crawler**: Menjelajahi aplikasi web untuk menemukan URL dan parameter yang relevan.
*   **Payload Generation**: Menghasilkan payload SQL Injection dan XSS yang umum.
*   **Response Analysis**: Menganalisis respons server untuk mendeteksi indikator kerentanan.
*   **AI-Powered Risk Analysis**: Menggunakan model AI (misalnya, Random Forest) dan deteksi anomali (Isolation Forest) untuk mengidentifikasi kerentanan berisiko tinggi.
*   **Reporting & Visualization**: Menyajikan hasil pemindaian dalam laporan yang jelas dan visualisasi data.

## Instalasi

Untuk menjalankan proyek ini, Anda perlu menginstal library Python berikut. Anda dapat melakukannya melalui `pip`:

```bash
pip install pandas numpy scikit-learn tensorflow keras beautifulsoup4 requests selenium matplotlib seaborn
```

## Cara Penggunaan

### 1. Inisialisasi dan Jalankan Pemindaian

Setelah menginstal dependensi, Anda dapat menggunakan kelas `AISecurityPipeline` untuk memulai pemindaian. Ganti `"https://example.com"` dengan URL target yang ingin Anda pindai. Pastikan Anda memiliki izin untuk memindai situs web target tersebut.

```python
# Inisialisasi pipeline dengan URL target dan jumlah halaman maksimum untuk di-crawl
target_url = "https://the-internet.herokuapp.com/" # Ganti dengan URL target Anda
max_pages_to_scan = 15 # Sesuaikan sesuai kebutuhan
pipeline = AISecurityPipeline(target_url, max_pages=max_pages_to_scan)

# Jalankan pemindaian keamanan
results = pipeline.run_security_scan()

# Hasilkan laporan dan visualisasi hasil
report = pipeline.generate_report(results)

# Tampilkan URL yang ditemukan
print("\nURL yang berhasil di-discovery:")
for i, url in enumerate(pipeline.discovered_urls, 1):
    print(f"{i}. {url}")
```

### 2. Memprediksi Keamanan URL Individu (Model AI)

Model AI yang terlatih dapat digunakan untuk memprediksi potensi risiko keamanan URL secara individu:

```python
# Contoh penggunaan fungsi prediksi keamanan URL
test_urls = [
    "https://the-internet.herokuapp.com/broken_images",
    "https://the-internet.herokuapp.com/forgot_password?param=test'OR'1'='1",
    "https://the-internet.herokuapp.com/dynamic_loading",
    "https://the-internet.herokuapp.com/challenging_dom"
]

print("\nPrediksi Keamanan URL:")
for url in test_urls:
    pred, prob = predict_url_security(url)
    status = "BERBAHAYA" if pred == 1 else "AMAN"
    print(f"{url} -> {status} (Confidence: {prob[1]*100:.2f}%)")
```

## Struktur Proyek

*   `AISecurityPipeline` class: Kelas utama yang mengelola proses crawling, pengujian kerentanan, dan analisis AI.
*   `generate_security_dataset()`: Fungsi untuk membuat dataset simulasi untuk melatih model AI.
*   `predict_url_security()`: Fungsi untuk memprediksi keamanan URL menggunakan model AI yang telah dilatih.

## Catatan Penting

*   **Gunakan Secara Bertanggung Jawab**: Jangan gunakan alat ini untuk memindai situs web tanpa izin eksplisit dari pemiliknya. Memindai tanpa izin dapat melanggar hukum.
*   **Lingkungan Pengujian**: Disarankan untuk menggunakan alat ini pada lingkungan pengujian atau situs web yang Anda miliki/kelola.
*   **Pembaruan**: Modul ini dapat terus dikembangkan dengan menambahkan deteksi kerentanan baru dan penyempurnaan model AI.
