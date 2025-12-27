import os, hashlib, json, base64
from flask import Flask, request, send_file, render_template, jsonify
import qrcode
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from flask import send_file

app = Flask(__name__)

# --- Folders ---
for folder in ["uploads", "signed", "keys"]:
    os.makedirs(folder, exist_ok=True)

# --- Keys ---
PRIVATE_KEY_PATH = "keys/private.pem"
PUBLIC_KEY_PATH  = "keys/public.pem"

if not os.path.exists(PRIVATE_KEY_PATH):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))
else:
    with open(PRIVATE_KEY_PATH, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(PUBLIC_KEY_PATH, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

# --- Utils ---
def sha256_file(file_bytes):
    h = hashlib.sha256()
    h.update(file_bytes)
    return h.hexdigest()

def sign_hash(pdf_hash):
    return private_key.sign(
        pdf_hash.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

# --- Routes ---
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/sign", methods=["POST"])
def sign_pdf():
    pdf = request.files["pdf"]
    pdf_bytes = pdf.read()

    # --- Calcul du hash ---
    pdf_hash = sha256_file(pdf_bytes)

    # --- Signature ---
    signature = sign_hash(pdf_hash)

    # --- Génération QR ---
    qr_payload = {
        "hash": pdf_hash,
        "signature": base64.b64encode(signature).decode(),
        "issuer": "MyFlaskServer"
    }
    qr_data = json.dumps(qr_payload)
    qr_img = qrcode.make(qr_data)

    # --- Sauvegarde PDF et QR ---
    pdf_filename = pdf.filename
    signed_pdf_path = os.path.join("signed", pdf_filename)
    with open(signed_pdf_path, "wb") as f:
        f.write(pdf_bytes)

    qr_name = f"qr_{os.path.splitext(pdf_filename)[0]}.png"
    qr_path = os.path.join("signed", qr_name)
    qr_img.save(qr_path)

    # --- Retourner le PDF signé automatiquement ---
    return send_file(
        signed_pdf_path,
        as_attachment=True,
        download_name=f"signed_{pdf_filename}"
    )

@app.route("/verify_pdf", methods=["POST"])
def verify_pdf():
    pdf = request.files["pdf"]
    qr_json = request.form.get("qr_data")
    if not qr_json:
        return jsonify({"error": "QR missing"}), 400
    try:
        qr = json.loads(qr_json)
    except:
        return jsonify({"valid": False, "message": "QR format invalid"})
    
    pdf_bytes = pdf.read()
    pdf_hash = sha256_file(pdf_bytes)
    if pdf_hash != qr["hash"]:
        return jsonify({"valid": False, "message": "Document modifié"})
    
    try:
        public_key.verify(
            base64.b64decode(qr["signature"]),
            qr["hash"].encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return jsonify({"valid": True, "message": "Document authentique"})
    except:
        return jsonify({"valid": False, "message": "Signature invalide"})

@app.route("/verify_qr", methods=["POST"])
def verify_qr():
    qr_json = request.form.get("qr_data")
    if not qr_json:
        return jsonify({"error": "QR missing"}), 400
    try:
        qr = json.loads(qr_json)
        public_key.verify(
            base64.b64decode(qr["signature"]),
            qr["hash"].encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return jsonify({"valid": True, "message": "QR authentique, document signé par serveur"})
    except:
        return jsonify({"valid": False, "message": "QR non valide"})

@app.route("/download/<filename>")
def download(filename):
    return send_file(os.path.join("signed", filename), as_attachment=True)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
