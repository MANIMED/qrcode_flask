import os
import hashlib
from flask import Flask, render_template, request, send_from_directory
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import qrcode
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from PyPDF2 import PdfReader, PdfWriter

app = Flask(__name__)

# ---------------------- Folders ----------------------
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SIGNED_FOLDER'] = 'signed'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['SIGNED_FOLDER'], exist_ok=True)

# ---------------------- RSA keys ----------------------
KEYS_PATH = "keys"
os.makedirs(KEYS_PATH, exist_ok=True)
PRIVATE_KEY_FILE = os.path.join(KEYS_PATH, "private_key.pem")
PUBLIC_KEY_FILE = os.path.join(KEYS_PATH, "public_key.pem")

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
    pdf_file = request.files["file"]
    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_file.filename)
    pdf_file.save(pdf_path)

    # Hash PDF
    with open(pdf_path, "rb") as f:
        pdf_bytes = f.read()
    pdf_hash = hashlib.sha256(pdf_bytes).hexdigest()

    # Sign hash
    signature = private_key.sign(
        pdf_hash.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    doc_id = pdf_hash[:12]
    os.makedirs(f"signed/{doc_id}", exist_ok=True)
    with open(f"signed/{doc_id}/hash.txt", "w") as f:
        f.write(pdf_hash)
    with open(f"signed/{doc_id}/signature.sig", "wb") as f:
        f.write(signature)

    # Generate QR code
    verification_url = request.host_url + f"verify_mobile?id={doc_id}"
    qr = qrcode.make(verification_url)
    qr_path = os.path.join(app.config['SIGNED_FOLDER'], f"qr_{doc_id}.png")
    qr.save(qr_path)

    # Create new PDF with QR code
    output_pdf_path = os.path.join(app.config['SIGNED_FOLDER'], f"signed_{pdf_file.filename}")
    reader = PdfReader(pdf_path)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    # Add a page with QR code
    c = canvas.Canvas("qr_page.pdf", pagesize=letter)
    c.drawImage(qr_path, 50, 500, width=150, height=150)
    c.save()

    qr_reader = PdfReader("qr_page.pdf")
    writer.add_page(qr_reader.pages[0])

    with open(output_pdf_path, "wb") as f:
        writer.write(f)

    return f"PDF signé avec QR Code : <a href='/download/{os.path.basename(output_pdf_path)}'>Télécharger</a>"

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
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return "<h2>Document AUTHENTIQUE ✅</h2>"
    except:
        return "<h2>Document NON VALIDE ❌</h2>"

# ---------------------- Launch ----------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
