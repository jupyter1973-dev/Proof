# -*- coding: utf-8 -*-

# Instalasi library yang diperlukan
!pip install pandas numpy scikit-learn tensorflow keras beautifulsoup4 requests selenium matplotlib seaborn

import pandas as pd
import numpy as np
import requests
from bs4 import BeautifulSoup
import re
import urllib.parse
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import matplotlib.pyplot as plt
import seaborn as sns
import time
import random
from collections import Counter
import warnings
warnings.filterwarnings('ignore')

print("Library berhasil diimpor!")

class AISecurityPipeline:
    def __init__(self, target_url, max_pages=10):
        self.target_url = target_url
        self.max_pages = max_pages
        self.discovered_urls = set()
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

    def normalize_url(self, url):
        """Normalisasi URL"""
        return urllib.parse.urljoin(self.target_url, url)

    def is_same_domain(self, url):
        """Memeriksa apakah URL berada dalam domain yang sama"""
        target_domain = urllib.parse.urlparse(self.target_url).netloc
        url_domain = urllib.parse.urlparse(url).netloc
        return url_domain == target_domain or url_domain.endswith('.' + target_domain)

    def intelligent_crawler(self):
        """Crawler cerdas dengan DFS terbatas"""
        print(f"[*] Memulai crawling untuk: {self.target_url}")
        queue = [self.target_url]
        self.discovered_urls.add(self.target_url)

        while queue and len(self.discovered_urls) < self.max_pages:
            url = queue.pop(0)
            try:
                print(f"[*] Mengakses: {url}")
                response = self.session.get(url, timeout=10)

                if response.status_code != 200:
                    print(f"[!] Status code {response.status_code} untuk {url}")
                    continue

                soup = BeautifulSoup(response.text, 'html.parser')

                # Ekstrak semua link
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if href.startswith('javascript:') or href.startswith('mailto:') or href == '#':
                        continue

                    full_url = self.normalize_url(href)

                    # Filter hanya URL yang relevan
                    if (self.is_same_domain(full_url) and
                        full_url not in self.discovered_urls and
                        not any(ext in full_url.lower() for ext in ['.pdf', '.jpg', '.png', '.css', '.js', '.ico'])):

                        self.discovered_urls.add(full_url)
                        queue.append(full_url)

                        if len(self.discovered_urls) >= self.max_pages:
                            break

                time.sleep(1)  # Menghindari rate limiting

            except Exception as e:
                print(f"[!] Error mengakses {url}: {str(e)}")

        print(f"[+] Ditemukan {len(self.discovered_urls)} URL")
        return list(self.discovered_urls)

    def generate_sql_injection_payloads(self):
        """Menghasilkan payload SQL injection menggunakan pola umum"""
        base_payloads = [
            "'",
            "''",
            "`",
            "\"",
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "' UNION SELECT NULL--"
        ]

        # Variasi payload
        variations = []
        for payload in base_payloads:
            variations.append(payload)
            variations.append(urllib.parse.quote(payload))
            variations.append(urllib.parse.quote_plus(payload))

        return variations

    def generate_xss_payloads(self):
        """Menghasilkan payload XSS menggunakan pola umum"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')"
        ]

        # Encode variations
        variations = []
        for payload in payloads:
            variations.append(payload)
            variations.append(urllib.parse.quote(payload))
            variations.append(urllib.parse.quote_plus(payload))

        return variations

    def analyze_response(self, response, payload, original_url):
        """Menganalisis respons untuk mendeteksi kerentanan"""
        vulnerabilities = []
        text_lower = response.text.lower()

        # Deteksi SQL injection
        sql_errors = [
            "sql syntax", "mysql_fetch", "ora-01756",
            "unclosed quotation mark", "sql command", "syntax error"
        ]

        if any(error in text_lower for error in sql_errors):
            vulnerabilities.append(('SQL Injection', payload, original_url))

        # Deteksi XSS - payload masih ada di response (reflected)
        if payload in response.text:
            vulnerabilities.append(('Reflected XSS', payload, original_url))

        # Deteksi error yang mengekspos informasi
        server_errors = ["php error", "warning:", "exception", "stack trace", "database error"]
        if any(error in text_lower for error in server_errors):
            vulnerabilities.append(('Information Disclosure', 'Server error exposed', original_url))

        return vulnerabilities

    def test_parameters(self, url):
        """Menguji parameter URL dengan payload berbahaya"""
        print(f"[*] Menguji parameter untuk: {url}")

        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)

        vulnerabilities = []

        # Jika URL memiliki parameter query
        if query_params:
            sql_payloads = self.generate_sql_injection_payloads()
            xss_payloads = self.generate_xss_payloads()

            # Test setiap parameter dengan setiap payload
            for param in query_params:
                print(f"  [*] Testing parameter: {param}")

                # Test dengan nilai normal dulu untuk baseline
                try:
                    normal_response = self.session.get(url, timeout=5)
                    time.sleep(0.5)
                except:
                    normal_response = None

                for payload in sql_payloads + xss_payloads:
                    # Buat URL dengan payload
                    test_params = query_params.copy()
                    test_params[param] = [payload]
                    new_query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        new_query,
                        parsed_url.fragment
                    ))

                    try:
                        response = self.session.get(test_url, timeout=8)
                        detected_vulns = self.analyze_response(response, payload, url)
                        vulnerabilities.extend(detected_vulns)

                        if detected_vulns:
                            print(f"    [!] Kerentanan ditemukan: {detected_vulns[0][0]}")

                        time.sleep(0.5)  # Menghindari rate limiting

                    except Exception as e:
                        print(f"    [!] Error testing {param}: {str(e)}")
                        continue

        return vulnerabilities

    def run_security_scan(self):
        """Menjalankan pemindaian keamanan lengkap"""
        print("[*] Memulai pemindaian keamanan AI-powered")

        # Langkah 1: Discovery
        urls = self.intelligent_crawler()

        if not urls:
            return {"status": "error", "message": "Tidak dapat menemukan URL"}

        # Langkah 2: Vulnerability testing
        all_vulnerabilities = []
        for url in urls:
            vulns = self.test_parameters(url)
            all_vulnerabilities.extend(vulns)

        # Langkah 3: Analisis dengan AI
        ai_analysis = self.ai_vulnerability_analysis(all_vulnerabilities)

        return ai_analysis

    def ai_vulnerability_analysis(self, vulnerabilities):
        """Analisis kerentanan dengan algoritma AI"""
        if not vulnerabilities:
            return {
                "status": "clean",
                "message": "Tidak ada kerentanan yang terdeteksi",
                "total_vulnerabilities": 0,
                "vulnerability_types": {},
                "high_risk_indices": [],
                "high_risk_vulnerabilities": []
            }

        # Hitung frekuensi setiap jenis kerentanan
        vuln_types = [vuln[0] for vuln in vulnerabilities]
        counter = Counter(vuln_types)

        # Analisis risiko dengan Isolation Forest
        X = np.array([[i] for i in range(len(vuln_types))])
        if len(vuln_types) > 1:  # Hanya jika ada lebih dari 1 vulnerability
            clf = IsolationForest(contamination=0.1, random_state=42)
            clf.fit(X)
            predictions = clf.predict(X)
            anomaly_indices = np.where(predictions == -1)[0]
            high_risk_vulns = [vulnerabilities[i] for i in anomaly_indices]
        else:
            anomaly_indices = [0]
            high_risk_vulns = vulnerabilities

        # Hasil analisis
        results = {
            "status": "vulnerabilities_found",
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerability_types": dict(counter),
            "high_risk_indices": anomaly_indices.tolist(),
            "high_risk_vulnerabilities": high_risk_vulns,
            "all_vulnerabilities": vulnerabilities
        }

        return results

    def generate_report(self, analysis_results):
        """Menghasilkan laporan pemindaian"""
        print("\n" + "="*60)
        print("LAPORAN PEMINDAIAN KEAMANAN AI-POWERED")
        print("="*60)

        print(f"\nTarget: {self.target_url}")
        print(f"Total URL yang di-scan: {len(self.discovered_urls)}")

        # Perbaikan: Cek jika kunci ada sebelum mengakses
        if 'total_vulnerabilities' in analysis_results:
            print(f"Total kerentanan yang ditemukan: {analysis_results['total_vulnerabilities']}")
        else:
            print("Total kerentanan yang ditemukan: 0")

        if 'vulnerability_types' in analysis_results and analysis_results['vulnerability_types']:
            print("\nJenis Kerentanan:")
            for vuln_type, count in analysis_results['vulnerability_types'].items():
                print(f"  - {vuln_type}: {count}")
        else:
            print("\nTidak ada jenis kerentanan yang ditemukan.")

        if ('high_risk_vulnerabilities' in analysis_results and
            analysis_results['high_risk_vulnerabilities']):
            print("\nKerentanan Berisiko Tinggi:")
            for i, (vuln_type, payload, url) in enumerate(analysis_results['high_risk_vulnerabilities'], 1):
                print(f"  {i}. {vuln_type}: {payload}")
                print(f"     URL: {url}")
        else:
            print("\nTidak ada kerentanan berisiko tinggi yang terdeteksi.")

        # Visualisasi jika ada data
        if ('vulnerability_types' in analysis_results and
            analysis_results['vulnerability_types']):
            self.visualize_results(analysis_results)
        else:
            print("\nTidak ada data untuk divisualisasikan.")

        return analysis_results

    def visualize_results(self, analysis_results):
        """Visualisasi hasil pemindaian"""
        if not analysis_results.get('vulnerability_types'):
            return

        # Pie chart untuk jenis kerentanan
        labels = list(analysis_results['vulnerability_types'].keys())
        sizes = list(analysis_results['vulnerability_types'].values())

        plt.figure(figsize=(12, 5))

        plt.subplot(1, 2, 1)
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
        plt.title('Distribusi Jenis Kerentanan')

        # Bar chart untuk jumlah kerentanan
        plt.subplot(1, 2, 2)
        plt.bar(labels, sizes, color=['red', 'orange', 'yellow', 'green'])
        plt.title('Jumlah Kerentanan per Jenis')
        plt.xticks(rotation=45)

        plt.tight_layout()
        plt.show()

# @title Masukkan URL target untuk di-scan
target_url = "https://the-internet.herokuapp.com" # @param {type:"string"}
max_pages = 15 # @param {type:"slider", min:5, max:50, step:5}

# Inisialisasi dan jalankan pipeline
print(f"Memulai pemindaian untuk: {target_url}")
pipeline = AISecurityPipeline(target_url, max_pages)
results = pipeline.run_security_scan()

# Hasil dan visualisasi
report = pipeline.generate_report(results)

# Tampilkan semua URL yang ditemukan
print("\nURL yang berhasil di-discovery:")
for i, url in enumerate(pipeline.discovered_urls, 1):
    print(f"{i}. {url}")

"""### Penerapan Cross-Validation

Untuk mendapatkan estimasi kinerja model yang lebih robust dan andal, kita akan menerapkan K-Fold Cross-Validation. Ini akan membagi dataset menjadi beberapa 'fold' dan melatih serta menguji model pada setiap kombinasi fold, kemudian merata-ratakan hasilnya.
"""

from sklearn.model_selection import KFold, cross_val_score

# Definisikan jumlah fold untuk cross-validation
kf = KFold(n_splits=5, shuffle=True, random_state=42)

# Lakukan cross-validation
# Skor akurasi
scores = cross_val_score(rf_model, X, y, cv=kf, scoring='accuracy')
print(f"Cross-validation Accuracy: {scores.mean():.2f} (+/- {scores.std():.2f})")

# Anda juga bisa memeriksa metrik lain seperti precision, recall, f1-score
# Misalnya, untuk presisi
# precision_scores = cross_val_score(rf_model, X, y, cv=kf, scoring='precision')
# print(f"Cross-validation Precision: {precision_scores.mean():.2f} (+/- {precision_scores.std():.2f})")

# Untuk recall
# recall_scores = cross_val_score(rf_model, X, y, cv=kf, scoring='recall')
# print(f"Cross-validation Recall: {recall_scores.mean():.2f} (+/- {recall_scores.std():.2f})")

# Untuk f1-score
# f1_scores = cross_val_score(rf_model, X, y, cv=kf, scoring='f1')
# print(f"Cross-validation F1-Score: {f1_scores.mean():.2f} (+/- {f1_scores.std():.2f})")

# Simulasi dataset untuk training model AI
def generate_security_dataset():
    """Membuat dataset simulasi untuk training model AI"""
    # Fitur: panjang URL, jumlah parameter, mengandung kata kunci berbahaya, dll.
    # Label: 0 = aman, 1 = berbahaya

    np.random.seed(42)
    n_samples = 1000

    # Generate fitur
    url_length = np.random.randint(10, 200, n_samples)
    num_params = np.random.randint(0, 5, n_samples)
    has_sql_keywords = np.random.choice([0, 1], n_samples, p=[0.7, 0.3])
    has_xss_keywords = np.random.choice([0, 1], n_samples, p=[0.8, 0.2])

    X = np.column_stack([url_length, num_params, has_sql_keywords, has_xss_keywords])

    # Generate labels berdasarkan aturan tertentu
    y = np.zeros(n_samples)
    y[(has_sql_keywords == 1) & (num_params > 0)] = 1
    y[(has_xss_keywords == 1) & (num_params > 0)] = 1
    y[(url_length > 100) & (num_params > 2)] = 1

    # Tambahkan noise
    noise = np.random.choice([0, 1], n_samples, p=[0.95, 0.05])
    y = np.clip(y + noise, 0, 1)

    return X, y

# Training model AI untuk klasifikasi URL
X, y = generate_security_dataset()
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Model Random Forest
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)

# Evaluasi model
y_pred = rf_model.predict(X_test)
print("Model AI Security Evaluation:")
print(classification_report(y_test, y_pred))

# Fungsi prediksi URL
def predict_url_security(url):
    """Memprediksi keamanan URL menggunakan model AI"""
    # Ekstrak fitur dari URL
    url_length = len(url)
    parsed_url = urllib.parse.urlparse(url)
    num_params = len(urllib.parse.parse_qs(parsed_url.query))

    # Periksa kata kunci SQL
    sql_keywords = ['union', 'select', 'insert', 'delete', 'drop', 'exec', 'sleep', 'waitfor']
    has_sql_keywords = any(keyword in url.lower() for keyword in sql_keywords)

    # Periksa kata kunci XSS
    xss_keywords = ['script', 'alert', 'onerror', 'onload', 'javascript', '<', '>']
    has_xss_keywords = any(keyword in url.lower() for keyword in xss_keywords)

    # Buat array fitur
    features = np.array([[url_length, num_params, int(has_sql_keywords), int(has_xss_keywords)]])

    # Prediksi
    prediction = rf_model.predict(features)
    probability = rf_model.predict_proba(features)

    return prediction[0], probability[0]

# Contoh penggunaan
test_urls = [
    "https://the-internet.herokuapp.com/broken_images",
    "https://the-internet.herokuapp.com/forgot_password",
    "https://the-internet.herokuapp.com/dynamic_loading",
    "https://the-internet.herokuapp.com/challenging_dom"
]

print("\nPrediksi Keamanan URL:")
for url in test_urls:
    pred, prob = predict_url_security(url)
    status = "BERBAHAYA" if pred == 1 else "AMAN"
    print(f"{url} -> {status} (Confidence: {prob[1]*100:.2f}%)")

# Contoh menjalankan pemindaian (gunakan website testing yang diperbolehkan)
# Catatan: Hanya gunakan pada website yang Anda miliki atau yang telah memberikan izin

# Untuk testing, kita bisa menggunakan website test yang aman
test_target = "https://the-internet.herokuapp.com/"  # Website testing

print("Memulai pemindaian keamanan...")
pipeline = AISecurityPipeline(test_target, max_pages=5)
results = pipeline.run_security_scan()
report = pipeline.generate_report(results)

