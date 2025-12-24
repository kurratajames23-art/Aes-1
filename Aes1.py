from flask import Flask, render_template_string, request, send_file
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import io

app = Flask(__name__)

# ================= KEY DERIVATION =================
def derive_key(text_key):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(text_key.encode())
    return digest.finalize()

# ================= HTML =================
html = """
<!DOCTYPE html>
<html>
<head>
<title>AES Document Encrypt / Decrypt</title>
<style>
body{
    font-family: Arial;
    background:#0b1220;
    color:white
}
.container{
    width:650px;
    margin:auto;
    margin-top:40px;
    padding:25px;
    background:#141e30;
    border-radius:15px
}
input, select{
    width:100%;
    padding:10px;
    border-radius:10px;
    border:none;
    margin-top:8px
}
button{
    padding:10px 20px;
    border:none;
    border-radius:10px;
    background:#4e73df;
    color:white;
    margin-top:12px;
    cursor:pointer
}
</style>
</head>

<body>
<div class="container">
<h2 align="center">AES Document Encrypt / Decrypt</h2>

<form method="post" enctype="multipart/form-data">
<label>Key</label>
<input name="key" required placeholder="Masukkan key bebas">

<label>Pilih File</label>
<input type="file" name="file" required>

<select name="mode">
    <option value="encrypt">Encrypt</option>
    <option value="decrypt">Decrypt</option>
</select>

<button type="submit">Proses</button>
</form>
</div>
</body>
</html>
"""

# ================= ROUTE UTAMA =================
@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        key = derive_key(request.form["key"])
        mode = request.form["mode"]
        file = request.files["file"]

        data = file.read()
        filename = file.filename

        # ---------- ENCRYPT ----------
        if mode == "encrypt":
            iv = os.urandom(16)
            cipher = Cipher(
                algorithms.AES(key),
                modes.CFB(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(data) + encryptor.finalize()

            output = io.BytesIO(iv + encrypted)
            output.seek(0)

            return send_file(
                output,
                as_attachment=True,
                download_name=f"encrypted_{filename}",
                mimetype="application/octet-stream"
            )

        # ---------- DECRYPT ----------
        else:
            iv = data[:16]
            ciphertext = data[16:]

            cipher = Cipher(
                algorithms.AES(key),
                modes.CFB(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()

            output = io.BytesIO(decrypted)
            output.seek(0)

            return send_file(
                output,
                as_attachment=True,
                download_name=f"decrypted_{filename}",
                mimetype="application/octet-stream"
            )

    return render_template_string(html)

# ================= RUN APP =================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
