import os
import hashlib
import json
import base64
import fitz  # PyMuPDF
import qrcode
from flask import Flask, request, send_file, render_template, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from flask_cors import CORS
import uuid

app = Flask(__name__)
CORS(app)

# --- Configuration des dossiers ---
for folder in ["uploads", "signed", "keys"]:
    os.makedirs(folder, exist_ok=True)

PRIVATE_KEY_PATH = "keys/private.pem"
PUBLIC_KEY_PATH  = "keys/public.pem"

# --- Génération/Chargement des clés RSA ---
if not os.path.exists(PRIVATE_KEY_PATH):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

with open(PRIVATE_KEY_PATH, "rb") as f: 
    private_key = serialization.load_pem_private_key(f.read(), password=None)
with open(PUBLIC_KEY_PATH, "rb") as f: 
    public_key = serialization.load_pem_public_key(f.read())

# ---------------------- LOGIQUE DE SIGNATURE ----------------------
def core_sign(pdf_file):
    pdf_bytes = pdf_file.read()
    # 1. Hash du contenu original
    pdf_hash = hashlib.sha256(pdf_bytes).hexdigest()
    
    # 2. Signature RSA avec SALT_LENGTH FIXE à 32
    signature = private_key.sign(
        pdf_hash.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), 
            salt_length=32  # Changé : MAX_LENGTH -> 32
        ),
        hashes.SHA256()
    )
    sig_b64 = base64.b64encode(signature).decode()
    qr_payload = {"hash": pdf_hash, "signature": sig_b64, "issuer": "SecureSign Server"}

    # 3. Insertion dans le PDF
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    doc.set_metadata({**doc.metadata, "subject": f"SIG:{pdf_hash}|{sig_b64}"})
    
    qr_temp = os.path.join("signed", "temp_qr.png")
    qrcode.make(json.dumps(qr_payload)).save(qr_temp)
    doc[0].insert_image(fitz.Rect(50, 50, 200, 200), filename=qr_temp)
    
    out_name = f"signed_{pdf_file.filename}"
    out_path = os.path.join("signed", out_name)
    doc.save(out_path)
    doc.close()
    return out_path, qr_payload

# ---------------------- ROUTES API ----------------------

@app.route("/api/verify_qr", methods=["POST"])
def verify_qr_api():
    data = request.get_json()
    try:
        qr_data = data.get("qrData")
        qr = json.loads(qr_data) if isinstance(qr_data, str) else qr_data
        
        # Vérification avec SALT_LENGTH FIXE à 32
        public_key.verify(
            base64.b64decode(qr["signature"]),
            qr["hash"].encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), 
                salt_length=32  # Changé : MAX_LENGTH -> 32
            ),
            hashes.SHA256()
        )
        return jsonify({"valid": True, "message": "Authentique"})
    except Exception as e:
        return jsonify({"valid": False, "message": "Non reconnu"}), 401

@app.route("/api/verify_pdf", methods=["POST"])
def verify_pdf_api():
    if 'pdf' not in request.files or 'qr_data' not in request.form:
        return jsonify({"valid": False, "message": "Données incomplètes"}), 400

    pdf_file = request.files['pdf']
    qr_data_raw = request.form.get('qr_data')

    try:
        qr = json.loads(qr_data_raw)
        qr_hash = qr.get("hash")
        qr_sig = qr.get("signature")

        pdf_bytes = pdf_file.read()
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        metadata = doc.metadata.get("subject", "")
        doc.close()

        if not metadata.startswith("SIG:"):
            return jsonify({"valid": False, "message": "Aucune signature valide."}), 401

        parts = metadata.replace("SIG:", "").split("|")
        pdf_stored_hash = parts[0]

        if qr_hash != pdf_stored_hash:
            return jsonify({"valid": False, "message": "Fraude détectée."}), 401

        # Vérification cryptographique avec SALT_LENGTH FIXE à 32
        public_key.verify(
            base64.b64decode(qr_sig),
            qr_hash.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), 
                salt_length=32  # Changé : MAX_LENGTH -> 32
            ),
            hashes.SHA256()
        )

        return jsonify({"valid": True, "message": "Document Authentique"})

    except Exception as e:
        return jsonify({"valid": False, "message": "Signature invalide."}), 401

# ... [Le reste des routes (index, sign, auth_qr, download) reste inchangé] ...

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/sign", methods=["POST"])
def sign_web():
    path, _ = core_sign(request.files["pdf"])
    return send_file(path, as_attachment=True)

@app.route("/api/sign", methods=["POST"])
def sign_api():
    path, qr_payload = core_sign(request.files["pdf"])
    return jsonify({
        "qr_data": qr_payload, 
        "download_url": f"/download/{os.path.basename(path)}"
    })

pending_auth_tokens = {}

@app.route("/api/get_auth_qr")
def get_auth_qr():
    token = str(uuid.uuid4())
    pending_auth_tokens[token] = True 
    auth_payload = {"auth_token": token, "action": "request_public_key"}
    img = qrcode.make(json.dumps(auth_payload))
    import io
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    return jsonify({"qr_image": qr_b64, "token": token})

@app.route("/api/fetch_public_key", methods=["POST"])
def fetch_public_key():
    data = request.get_json()
    token = data.get("auth_token")
    if token in pending_auth_tokens:
        del pending_auth_tokens[token]
        with open(PUBLIC_KEY_PATH, "r") as f:
            pub_key_content = f.read()
        return jsonify({"success": True, "public_key": pub_key_content})
    else:
        return jsonify({"success": False, "message": "Jeton invalide"}), 403

@app.route("/download/<filename>")
def download(filename):
    return send_file(os.path.join("signed", filename), as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))