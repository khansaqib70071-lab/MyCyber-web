import ipaddress
import re
from urllib.parse import unquote, urlparse
from flask import Flask, flash, redirect, render_template, request, url_for
from scanner import scan_website_security
app = Flask(__name__)
# سیکیورٹی کیز اور فلیکسیبل ٹیمپلیٹ ری لوڈنگ
app.secret_key = "mycyber-tool-dev-key-change-in-production"
app.config['TEMPLATES_AUTO_RELOAD'] = True

# ڈینجرس کی ورڈز جو ویب سائٹ ہیکنگ یا فشنگ کو پکڑتے ہیں
DANGEROUS_KEYWORDS = (
    "paypal", "secure-login", "update-account", "verify", 
    "banking", "signin", "wp-admin", "checkpoint"
)

@app.route('/')
def home():
    # یہ لائن فرنٹ اینڈ کے ۳۵۴ لائنوں والے ڈیزائن کو لائیو رینڈر کرے گی
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan_url():
    # 1. کسٹمر جو ویب سائٹ فارم میں لکھے گا وہ حاصل کریں
    target_url = request.form.get('url', '').strip()
    
    if not target_url:
        return render_template('index.html', error="Please enter a valid URL")
        
    # 2. یہاں آپ کا اسکینر رن ہوگا
    result = scan_website_security(target_url)
    
    # 3. رزلٹ کو انڈیکس پیج پر واپس بھیجیں
    return render_template('index.html', scanning_result=result)
if __name__ == '__main__':
    app.run(debug=True, port=5000)
# یہ آپ کی app.py کی آخری لائن ہونی چاہیے
app = app