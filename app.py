# SecureSnap: Cybersecurity Framework for Online Stock Photo E-commerce Platform

from flask import Flask, request, jsonify, render_template, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import jwt, datetime, os, hashlib, io, logging
from PIL import Image, ImageDraw, ImageFont

# ------------------------------------------------
# 🔐 CONFIGURATION
# ------------------------------------------------

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey_secureSnap2025'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///securesnap.db'
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)

# ------------------------------------------------
# 🔐 ENCRYPTION KEY MANAGEMENT
# ------------------------------------------------
if os.path.exists("secret.key"):
    with open("secret.key", "rb") as key_file:
        key = key_file.read()
else:
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

cipher = Fernet(key)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# ------------------------------------------------
# 🧩 DATABASE MODELS
# ------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)

class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    encrypted_path = db.Column(db.String(200))
    hash = db.Column(db.String(64))

# ------------------------------------------------
# 🧱 UTILITIES
# ------------------------------------------------
def watermark_image(input_image, watermark_text="© SecureSnap"):
    image = Image.open(input_image).convert("RGBA")
    watermark = Image.new("RGBA", image.size)
    draw = ImageDraw.Draw(watermark)
    font = ImageFont.load_default()
    width, height = image.size
    draw.text((width - 150, height - 30), watermark_text, fill=(255, 255, 255, 128), font=font)
    combined = Image.alpha_composite(image, watermark)
    watermarked_path = os.path.join(app.config['UPLOAD_FOLDER'], "watermarked_" + os.path.basename(input_image))
    combined.convert("RGB").save(watermarked_path)
    return watermarked_path

def encrypt_file(file_path):
    with open(file_path, 'rb') as file:
        data = file.read()
    encrypted_data = cipher.encrypt(data)
    encrypted_path = file_path + ".enc"
    with open(encrypted_path, 'wb') as enc_file:
        enc_file.write(encrypted_data)
    return encrypted_path

def decrypt_file(encrypted_path):
    with open(encrypted_path, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = cipher.decrypt(encrypted_data)
    return io.BytesIO(decrypted_data)

# ------------------------------------------------
# 🧍 USER REGISTRATION & LOGIN
# ------------------------------------------------
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_pw = generate_password_hash(data['password'], method='pbkdf2:sha256')
    user = User(username=data['username'], email=data['email'], password=hashed_pw)
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User registered successfully!"})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({"message": "Invalid credentials"}), 401
    token = jwt.encode(
        {'user': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)},
        app.config['SECRET_KEY'], algorithm='HS256'
    )
    return jsonify({"token": token})

# ------------------------------------------------
# 📸 IMAGE UPLOAD (ENCRYPTION + WATERMARKING)
# ------------------------------------------------
@app.route('/upload', methods=['POST'])
def upload_photo():
    token = request.headers.get('x-access-token')
    if not token:
        return jsonify({"message": "Token missing"}), 401
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = data['user']
    except Exception as e:
        print("JWT Error:", e)
        return jsonify({"message": "Token invalid"}), 401

    if 'photo' not in request.files:
        return jsonify({"message": "No photo uploaded"}), 400

    photo = request.files['photo']
    filename = photo.filename
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    photo.save(filepath)

    # Watermark + Encrypt
    watermarked_path = watermark_image(filepath)
    encrypted_path = encrypt_file(watermarked_path)

    # Hash for integrity
    with open(filepath, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    new_photo = Photo(filename=filename, owner_id=user_id, encrypted_path=encrypted_path, hash=file_hash)
    db.session.add(new_photo)
    db.session.commit()

    return jsonify({"message": "✅ Photo securely uploaded and encrypted!"})

# ------------------------------------------------
# 💳 SECURE PAYMENT SIMULATION (Tokenized)
# ------------------------------------------------
@app.route('/payment', methods=['POST'])
def payment():
    data = request.get_json()
    tokenized_card = hashlib.sha256(data['card_number'].encode()).hexdigest()
    logging.info(f"Payment processed for token: {tokenized_card[:8]}****")
    return jsonify({"message": "Payment successful", "transaction_token": tokenized_card[:12]})

# ------------------------------------------------
# 🧠 INTRUSION DETECTION SIMULATION
# ------------------------------------------------
@app.route('/monitor', methods=['GET'])
def monitor():
    suspicious_logs = []
    with open("access.log", "a+") as log:
        log.write(f"Access from {request.remote_addr}\n")
    if request.remote_addr.startswith("192.168"):
        suspicious_logs.append({"ip": request.remote_addr, "alert": "Internal unauthorized access"})
    return jsonify({"status": "running", "alerts": suspicious_logs})

# ------------------------------------------------
# 🚀 RUN APP
# ------------------------------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
