# 🛡️ SafeScan QR: Anti-Quishing & Phishing Defense

SafeScan QR is a cybersecurity application designed to protect users from **Quishing** (QR Phishing). Unlike standard scanners, this tool unmasks hidden redirects and scans the final destination against 70+ security engines to ensure safety before you visit a site.

## ✨ Key Features
* **QR Decoding:** Uses OpenCV and Pyzbar to extract data from uploaded images.
* **URL Unmasking:** Automatically follows shortened links (like bit.ly or qrco.de) to reveal the actual destination.
* **Threat Intelligence:** Integrated with the **VirusTotal API** for real-time malicious URL detection.
* **Direct Download Detection:** Automatically flags URLs that trigger risky file downloads (.exe, .apk, .zip).
* **Clipboard Protection:** Encourages secure opening of links to prevent clipboard hijacking.

## 🚀 Tech Stack
* **Language:** Python 3
* **Web Framework:** Flask
* **Libraries:** OpenCV, Pyzbar, Requests, NumPy
* **API:** VirusTotal v3

## 🛠️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/raghav19sh/Qishing-qr-phishing.git](https://github.com/raghav19sh/Qishing-qr-phishing.git)
   cd Qishing-qr-phishing