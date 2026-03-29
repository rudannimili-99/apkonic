from http import client

from flask import Flask, request, jsonify, render_template
import os
import re
from pymongo import MongoClient
from datetime import datetime

app = Flask(__name__, template_folder="templates", static_folder="static")
# MongoDB Atlas connection
client = MongoClient("mongodb+srv://rudanimili1118_db_user:MiliRudani1234@cluster0.vweh5lh.mongodb.net/?retryWrites=true&w=majority&serverSelectionTimeoutMS=5000")
db = client["apkonic"]
collection = db["logs"]
try:
    client.admin.command('ping')
    print("Connected to MongoDB Atlas successfully!")
except Exception as e:
    print("Error connecting to MongoDB Atlas:", e)

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
        print("FORM RECEIVED:", request.form)

        name = request.form.get("name")
        email = request.form.get("email")
        subject = request.form.get("subject")
        message = request.form.get("message")

        try:
            
            with open("message.txt", "a", encoding="utf-8") as f:
              f.write("----- NEW MESSAGE -----\n")
              f.write(f"Name: {name}\n")
              f.write(f"Email: {email}\n")
              f.write(f"Subject: {subject}\n")
              f.write(f"Message: {message}\n")
              f.write("------------------------\n\n")
            print("Saved message ✔")
        except Exception as e:
            print("Error:", e)

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
    try:
      with open("activity_logs.txt", "a", encoding="utf-8") as f:
          f.write(f"""
 ----------------SMS SCAN----------------       
Time   : {datetime.now()}
Message: {message}
Risk   : {risk_score}
Result : {result}
-------------------

      """)
          print("file saved")
    except Exception as e:
          print("Error saving file:", e)
    
    try:
      collection.insert_one({
        "type": "sms",
        "message": message,
        "risk_score": risk_score,
        "reasons": reasons,
        "timestamp": datetime.utcnow()
        })
      print("MongoDB saved ✔",result.inserted_id)
    except Exception as e:
      print("MongoDB error:", e)


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

    # ✅ FILE SAVE
    try:
        with open("activity_logs.txt", "a", encoding="utf-8") as f:
            f.write(f"""
------------------SENDER VERIFY------------------
Time    : {datetime.now()}
Sender  : {sender}
Verdict : {verdict}
================================================
""")
        print("file saved")
    except Exception as e:
        print("Error saving file:", e)

    # ✅ MONGODB SAVE
    try:
        result = collection.insert_one({
            "type": "sender",
            "sender": sender,
            "verdict": verdict,
            "timestamp": datetime.utcnow()
        })
        print("MongoDB saved ✓", result.inserted_id)
    except Exception as e:
        print("MongoDB error ❌:", e)

    return jsonify({"verdict": verdict})
     


# ================= APK SCAN =================
@app.route("/scan_apk", methods=["POST"])
def scan_apk():
    try:
        # Get file
        if "apk" not in request.files:
            return jsonify({"result": "No file uploaded"})

        file = request.files["apk"]

        # Save file
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)

        # Get size
        filesize = os.path.getsize(filepath)

        # Simple logic
        if filesize < 5 * 1024 * 1024:
            result = "APK Looks Safe"
            color = "green"
        else:
            result = "APK Might Be Suspicious"
            color = "orange"

        # Save to text file
        try:
            with open("activity_logs.txt", "a", encoding="utf-8") as f:
                f.write(f"""
======== APK UPLOAD ========
Time   : {datetime.now()}
File   : {file.filename}
Size   : {filesize} bytes
Result : {result}
============================
""")
            print("APK log saved")

        except Exception as e:
            print("APK log error:", e)

        # Save to MongoDB
        try:
            collection.insert_one({
                "type": "apk",
                "filename": file.filename,
                "size": filesize,
                "result": result,
                "timestamp": datetime.utcnow()
            })
            print("MongoDB saved ✓")

        except Exception as e:
            print("MongoDB error:", e)

        # Response
        return jsonify({
            "result": result,
            "size": filesize,
            "color": color
        })

    except Exception as e:
        print("Scan error:", e)
        return jsonify({"result": "Error scanning APK"})


# ================= RUN =================
if __name__ == "__main__":
    app.run(debug=True)
