import os
import hashlib
from flask import Flask, render_template, request, send_from_directory
import qrcode
import fitz  # PyMuPDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# ---------------------- Initialisation ----------------------
app = Flask(__name__)

# Folders
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SIGNED_FOLDER'] = 'signed'

# Crée les dossiers automatiquement s’ils n’existent pas
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['SIGNED_FOLDER'], exist_ok=True)

# ---------------------- Clés RSA ----------------------
KEYS_PATH = "keys"
os.makedirs(KEYS_PATH, exist_ok=True)
PRIVATE_KEY_FILE = os.path.join(KEYS_PATH, "private_key.pem")
PUBLIC_KEY_FILE = os.path.join(KEYS_PATH, "public_key.pem")

# Générer les clés si elles n'existent pas
if not os.path.exists(PRIVATE_KEY_FILE):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
else:
    with open(PRIVATE_KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(PUBLIC_KEY_FILE, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

# ---------------------- Routes ----------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/sign", methods=["POST"])
def sign_pdf():
    pdf = request.files["file"]
    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf.filename)
    pdf.save(pdf_path)

    # Calculer hash du PDF
    with open(pdf_path, "rb") as f:
        data = f.read()
    pdf_hash = hashlib.sha256(data).hexdigest()

    # Signer le hash
    signature = private_key.sign(
        pdf_hash.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # ID unique pour le document
    doc_id = pdf_hash[:12]

    # Sauvegarder signature et hash
    os.makedirs(f"signed/{doc_id}", exist_ok=True)
    with open(f"signed/{doc_id}/hash.txt", "w") as f:
        f.write(pdf_hash)
    with open(f"signed/{doc_id}/signature.sig", "wb") as f:
        f.write(signature)

    # Générer QR Code avec URL Railway
    verification_url = request.host_url + f"verify_mobile?id={doc_id}"
    qr = qrcode.make(verification_url)
    qr_path = os.path.join(app.config['SIGNED_FOLDER'], f"qr_{doc_id}.png")
    qr.save(qr_path)

    # Ajouter QR Code au PDF
    doc = fitz.open(pdf_path)
    page = doc[0]
    rect = fitz.Rect(50, 50, 200, 200)
    page.insert_image(rect, filename=qr_path)
    signed_pdf_path = os.path.join(app.config['SIGNED_FOLDER'], f"signed_{pdf.filename}")
    doc.save(signed_pdf_path)
    doc.close()

    # Retourner lien de téléchargement
    return f"PDF signé avec QR Code : <a href='/download/{os.path.basename(signed_pdf_path)}'>Télécharger le PDF</a>"


@app.route("/download/<filename>")
def download_file(filename):
    return send_from_directory(app.config['SIGNED_FOLDER'], filename, as_attachment=True)


@app.route("/verify_mobile")
def verify_mobile():
    doc_id = request.args.get("id")
    if not doc_id:
        return "<h2>QR Code invalide</h2>"

    try:
        with open(f"signed/{doc_id}/hash.txt", "r") as f:
            hash_pdf = f.read()
        with open(f"signed/{doc_id}/signature.sig", "rb") as f:
            signature = f.read()

        public_key.verify(
            signature,
            hash_pdf.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return "<h2>Document AUTHENTIQUE </h2>"

    except:
        return "<h2>Document NON VALIDE </h2>"


# ---------------------- Lancement ----------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
