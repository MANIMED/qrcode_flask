import os
import hashlib
import json
import base64
import fitz  # PyMuPDF
import qrcode
from flask import Flask, request, send_file, render_template, jsonify, redirect
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# --- Configuration Dossiers ---
for folder in ["uploads", "signed", "keys"]:
    os.makedirs(folder, exist_ok=True)

# --- Gestion des Clés ---
PRIVATE_KEY_PATH = "keys/private.pem"
PUBLIC_KEY_PATH  = "keys/public.pem"

if not os.path.exists(PRIVATE_KEY_PATH):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

with open(PRIVATE_KEY_PATH, "rb") as f: private_key = serialization.load_pem_private_key(f.read(), password=None)
with open(PUBLIC_KEY_PATH, "rb") as f: public_key = serialization.load_pem_public_key(f.read())

# ---------------------- LOGIQUE COMMUNE ----------------------
def core_sign(pdf_file):
    pdf_bytes = pdf_file.read()
    pdf_hash = hashlib.sha256(pdf_bytes).hexdigest()
    signature = private_key.sign(pdf_hash.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    qr_payload = {"hash": pdf_hash, "signature": base64.b64encode(signature).decode(), "issuer": "MyFlaskServer"}
    
    pdf_temp = os.path.join("signed", "temp.pdf")
    qr_temp = os.path.join("signed", "temp_qr.png")
    qrcode.make(json.dumps(qr_payload)).save(qr_temp)
    with open(pdf_temp, "wb") as f: f.write(pdf_bytes)
    
    doc = fitz.open(pdf_temp)
    doc[0].insert_image(fitz.Rect(50, 50, 200, 200), filename=qr_temp)
    out_name = f"signed_{pdf_file.filename}"
    out_path = os.path.join("signed", out_name)
    doc.save(out_path)
    doc.close()
    return out_path, qr_payload

def core_verify(pdf_bytes, qr_json):
    qr = json.loads(qr_json)
    pdf_hash = hashlib.sha256(pdf_bytes).hexdigest()
    if pdf_hash != qr["hash"]: return False, "Document modifié"
    public_key.verify(base64.b64decode(qr["signature"]), qr["hash"].encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    return True, "Document authentique"

# ---------------------- VERSIONS FORMULAIRE (WEB) ----------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/sign", methods=["POST"])
def sign_web():
    path, _ = core_sign(request.files["pdf"])
    return send_file(path, as_attachment=True)

@app.route("/verify_pdf", methods=["POST"])
def verify_pdf_web():
    pdf = request.files["pdf"]
    qr_data = request.form.get("qr_data")
    try:
        success, msg = core_verify(pdf.read(), qr_data)
        return f"<h2>Résultat : {msg}</h2><a href='/'>Retour</a>"
    except:
        return "<h2>Erreur de vérification</h2><a href='/'>Retour</a>"

@app.route("/verify_qr", methods=["POST"])
def verify_qr_web():
    qr_json = request.form.get("qr_data")
    try:
        qr = json.loads(qr_json)
        public_key.verify(base64.b64decode(qr["signature"]), qr["hash"].encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return "<h2>QR Valide</h2><a href='/'>Retour</a>"
    except:
        return "<h2>QR Invalide</h2><a href='/'>Retour</a>"

# ---------------------- VERSIONS API (JSON / IONIC) ----------------------
@app.route("/api/sign", methods=["POST"])
def sign_api():
    path, qr_payload = core_sign(request.files["pdf"])
    return jsonify({
        "status": "success",
        "qr_data": qr_payload,
        "filename": os.path.basename(path),
        "download_url": f"/download/{os.path.basename(path)}"
    })

@app.route("/api/verify_pdf", methods=["POST"])
def verify_pdf_api():
    try:
        pdf = request.files["pdf"]
        qr_data = request.form.get("qr_data")
        success, msg = core_verify(pdf.read(), qr_data)
        return jsonify({"valid": success, "message": msg})
    except Exception as e:
        return jsonify({"valid": False, "message": str(e)}), 400

@app.route("/api/verify_qr", methods=["POST"])
def verify_qr_api():
    data = request.get_json()
    qr_json = data.get("qrData")
    try:
        qr = json.loads(qr_json)
        public_key.verify(base64.b64decode(qr["signature"]), qr["hash"].encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return jsonify({"valid": True, "message": "QR Authentique"})
    except:
        return jsonify({"valid": False, "message": "QR Invalide"}), 401

# --- Utilitaires ---
@app.route("/download/<filename>")
def download(filename):
    return send_file(os.path.join("signed", filename), as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)