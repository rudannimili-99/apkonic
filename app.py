from flask import Flask, request, jsonify, render_template
import os
import re

app = Flask(__name__, template_folder="templates", static_folder="static")

# Upload folder
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ================= HOME =================
@app.route("/")
def home():
    return render_template("index.html")


# ================= SCAN PAGE =================
@app.route("/scan")
def scan():
    return render_template("scan.html")


# ================= FEATURES =================
@app.route("/features")
def features():
    return render_template("features.html")


# ================= ABOUT =================
@app.route("/aboutus")
def aboutus():
    return render_template("aboutus.html")


# ================= CONTACT =================
@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        print("FORM RECEIVED")
        name = request.form.get("name")
        email = request.form.get("email")
        subject = request.form.get("subject")
        message = request.form.get("message")

        with open("messages.txt", "w", encoding="utf-8") as f:
            f.write(f"\nName: {name}\nEmail: {email}\nSubject: {subject}\nMessage: {message}\n")

        print("Saved message to messages.txt")

        return render_template("contact.html", message="Message received successfully!")

    return render_template("contact.html")


# ================= SMS SCAN =================
@app.route("/scan_sms", methods=["POST"])
def scan_sms():
    data = request.get_json()
    message = data.get("message", "").lower()

    risk_score = 0
    reasons = []

    # 1. Suspicious keywords
    keywords = ["win", "lottery", "free", "urgent", "click", "offer", "prize"]
    if any(k in message for k in keywords):
        risk_score += 2
        reasons.append("Suspicious keywords detected")

    # 2. External links
    if re.search(r"http[s]?://", message):
        risk_score += 2
        reasons.append("Contains external link")

    # 3. Urgency words
    urgency = ["urgent", "immediately", "act now", "limited time"]
    if any(u in message for u in urgency):
        risk_score += 1
        reasons.append("Creates urgency")

    # Final result
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
        "SBIUPI", "AXISBK", "HDFCBK", "ICICIB",
        "JIOPAY", "PAYTMB", "GPAY", "KOTAKBK",
        "AMAZON", "FLIPKART", "ZOMATO", "SWIGGY",
        "UIDAI", "IRCTC", "AIRINDIA", "GOOGLE", "APPLE"
    ]

    if any(trusted in sender for trusted in trusted_senders):
        verdict = "Trusted / Likely Legitimate Sender"
    else:
        verdict = "Unknown or Suspicious Sender"

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
        return jsonify({"result": "Not a valid APK file"})

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    filesize = os.path.getsize(filepath)

    # Simple logic
    if filesize < 5 * 1024 * 1024:
        result = "APK Looks Safe"
        color = "green"
    else:
        result = "APK Might Be Suspicious"
        color = "orange"

    return jsonify({
        "result": result,
        "size": filesize,
        "color": color
    })


# ================= RUN =================
if __name__ == "__main__":
    app.run(debug=True)
