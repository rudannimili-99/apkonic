from email.mime import message

from flask import Flask, request, jsonify, render_template
import os
print(os.listdir("templates"))
app = Flask(__name__,template_folder="templates")

@app.route("/")
def home():
    return render_template("index.html")
@app.route("/scan")
def scan():
    return render_template("scan.html")
@app.route("/features")
def features():
    return render_template("features.html")
@app.route("/aboutus")
def aboutus():
    return render_template("aboutus.html")
@app.route("/contact", methods=["GET","POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        subject = request.form.get("subject")
        message = request.form.get("message")
        with open("messages.txt", "a") as f:
            f.write(f"\nName: {name}\nEmail: {email}\nSubject: {subject}\nMessage: {message}\n---\n")
            print("New Message:")
            print(name, email, subject, message)

        return render_template("contact.html", message="Message received successfully!")

        return render_template("contact.html")
    
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ================= SMS SCAN =================
import re

@app.route('/scan_sms', methods=['POST'])
def scan_sms():
    data = request.get_json()
    message = data.get('message', '').lower()

    risk_score = 0
    reasons = []

    # 🚨 1. Suspicious Keywords
    keywords = ["win", "lottery", "free", "urgent", "click", "offer", "prize"]
    if any(k in message for k in keywords):
        risk_score += 2
        reasons.append("Suspicious keywords detected")

    # 🚨 2. Fake Links
    if re.search(r'http[s]?://', message):
        risk_score += 2
        reasons.append("Contains external link")

    # 🚨 3. Urgency / Pressure
    urgency = ["urgent", "immediately", "act now", "limited time"]
    if any(u in message for u in urgency):
        risk_score += 2
        reasons.append("Creates urgency pressure")

    # 🚨 4. OTP / Bank Scam
    bank_words = ["otp", "bank", "account", "verify", "password"]
    if any(b in message for b in bank_words):
        risk_score += 2
        reasons.append("Sensitive info request (OTP/Bank)")

    # 🚨 5. Suspicious Sender Format
    if re.search(r'\d{10}', message):
        risk_score += 1
        reasons.append("Unknown mobile number detected")

# 🔗 URL Detection
    urls = re.findall(r'(https?://[^\s]+|www\.[^\s]+)', message)

    if urls:
        risk_score += 2
        reasons.append("Contains URL link")

    # Short links
    short_domains = ["bit.ly", "tinyurl", "goo.gl", "t.co"]
    if any(domain in message for domain in short_domains):
        risk_score += 2
        reasons.append("Uses shortened URL (suspicious)")

    # phishing words with link
    suspicious_words = ["verify", "login", "update", "secure"]
    if any(word in message for word in suspicious_words):
        risk_score += 1
        reasons.append("URL may lead to phishing page")

    # 🎯 FINAL RESULT
    if risk_score <= 2:
        result = "Safe Message"
        color = "green"
    elif risk_score <= 5:
        result = "Suspicious Message"
        color = "orange"
    else:
        result = "Phishing / Dangerous Message"
        color = "red"
    
    return jsonify({
        "result": result,
        "risk_score": risk_score,
        "reasons": reasons,
        "color": color
    })

# ================= SENDER VERIFY =================
@app.route("/verify_sender", methods=["POST"])
def verify_sender():

    data = request.get_json()

    if not data or "sender" not in data:
        return jsonify({"verdict": "No sender received"})

    sender = data["sender"].upper()

    trusted_senders = [
        "SBIUPI","AXISBK","HDFCBK","ICICIB",
        "JIOPAY","PAYTMB","GPAY","KOTAKBK",
        "AMAZON","FLIPKART","ZOMATO","SWIGGY",
        "UIDAI","IRCTC","AIRINDIA","GOOGLE","APPLE",
    ]

    if any(trusted in sender for trusted in trusted_senders):
        verdict = "✅ Trusted / Likely Legitimate Sender"
    else:
        verdict = "⚠️ Unknown or Suspicious Sender"

    return jsonify({"verdict": verdict})

# ================= APK SCAN =================
@app.route("/scan_apk", methods=["POST"])
def scan_apk():

    if "apk" not in request.files:
        return jsonify({"result": "No file uploaded"})

    file = request.files["apk"]

    if file.filename == "":
        return jsonify({"result": "No file selected"})

    if not file.filename.lower().endswith(".apk"):
        return jsonify({"result": "❌ Not a valid APK file"})

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    filesize = os.path.getsize(filepath)

    risk_score = 0
    reasons = []

    # 1️⃣ File size analysis
    if filesize < 50000:
        risk_score += 2
        reasons.append("Very small file size")

    if filesize > 200000000:
        risk_score += 1
        reasons.append("Unusually large APK")

    # 2️⃣ Suspicious filename check
    suspicious_names = ["crack", "mod", "hack", "premium", "free", "patched"]
    for word in suspicious_names:
        if word in file.filename.lower():
            risk_score += 2
            reasons.append(f"Suspicious keyword in filename: {word}")

    # 3️⃣ Basic content keyword scan (fake scan simulation)
    with open(filepath, "rb") as f:
        content = f.read().lower()

        suspicious_strings = [
            b"getdeviceid",
            b"sendtextmessage",
            b"http://",
            b"https://",
            b"exec",
            b"root",
        ]

        for s in suspicious_strings:
            if s in content:
                risk_score += 1
                reasons.append(f"Suspicious code pattern: {s.decode()}")

    # 🔥 Final Decision
    if risk_score >= 5:
        result = "🚨 Dangerous APK"
        color = "red"
    elif risk_score >= 3:
        result = "⚠️ Suspicious APK"
        color = "orange"
    else:
        result = "✅ APK Looks Safe"
        color = "green"

    return jsonify({
        "result": result,
        "risk_score": risk_score,
        "reasons": reasons,
        "color": color
    })
if __name__ == "__main__":
    app.run(debug=True)
