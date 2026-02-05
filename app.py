import os, cv2, base64, requests, time, numpy as np
import requests
from flask import Flask, render_template, request
from pyzbar.pyzbar import decode
from dotenv import load_dotenv

load_dotenv() 

VT_API_KEY = os.getenv("VT_API_KEY")

def unshorten_url(url):
    """Follows redirects to find where the QR code is REALLY taking you."""
    try:
        # We send a request but tell it not to download the whole page (head only)
        # allow_redirects=True follows the link until it hits the final website
        response = requests.head(url, allow_redirects=True, timeout=5)
        return response.url
    except:
        # If it fails, just return the link found in the QR
        return url
app = Flask(__name__)

def check_url_safety(url):
    headers = {"x-apikey": VT_API_KEY, "accept": "application/json"}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(report_url, headers=headers)
        if response.status_code == 200:
            return response.json()['data']['attributes'].get('last_analysis_stats')
        if response.status_code == 404:
            requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={'url': url})
            return "scanning"
        return "unrated"
    except Exception as e:
        print(f"VirusTotal API Error: {e}")
        return "error"

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        file = request.files.get('file')
        if file:
            try:
                file.seek(0)
                file_bytes = np.frombuffer(file.read(), np.uint8)
                img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)

                if img is None:
                    result = "bad_image"
                else:
                    # THIS LINE DEFINES 'qrs'
                    qrs = decode(img) 
                    
                    if qrs:
                        # Get the hidden link
                        qr_link = qrs[0].data.decode('utf-8')
                        
                        # Follow redirects (The "Unmasking" part)
                        final_destination = unshorten_url(qr_link)
                        
                        # Scan the final link
                        stats = check_url_safety(final_destination)
                        
                        result = {"url": final_destination, "stats": stats}
                    else:
                        result = "no_qr"
            except Exception as e:
                # CHECK YOUR TERMINAL FOR THIS OUTPUT:
                print("\n!!! CRASH DETECTED !!!")
                print(f"Error details: {e}\n")
                result = "crash"

    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True, port=5000)