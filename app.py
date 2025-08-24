from flask import Flask, request, jsonify

app = Flask(__name__)

def get_client_ip():
    xff = request.headers.get('X-Forwarded-For')
    if xff:
        return xff.split(',')[0].strip()
    else:
        return request.remote_addr

@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "response received from server"})

@app.route("/apkonic", methods=["GET"])
def apkonic():
    return jsonify({
        "from": "server",
        "message": "apkonic: server response OK",
        "clientIp": get_client_ip()
    })

if __name__ == "__main__":

    app.run(host="0.0.0.0",debug=True,port=3000)

