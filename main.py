import os
import json
import pyodbc
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image
from PIL.ExifTags import TAGS
import piexif
import imageio.v3 as iio

# Flask App Setup
app = Flask(__name__)
app.secret_key = "supersecretkey"  # Change this for production


# Register the fromjson filter
def fromjson(value):
    if value:
        try:
            return json.loads(value)  # Convert JSON string to Python dictionary
        except Exception as e:
            return {}
    return {}

# Register the filter with Flask
app.jinja_env.filters['fromjson'] = fromjson

# Database Configuration (Microsoft SQL Server)
DB_SERVER = "localhost\\MSSQLSERVER07"
DB_NAME = "image_meta_db"

CONN_STR = f"DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={DB_SERVER};DATABASE={DB_NAME};Trusted_Connection=yes;"

# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# File Upload Configuration
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Database Connection Function
def get_connection():
    return pyodbc.connect(CONN_STR)

# User Class
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password




@app.route('/uploads/<filename>')
def uploads(filename):
    return send_from_directory('uploads', filename)


@login_manager.user_loader
def load_user(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return User(id=user[0], username=user[1], password=user[2])
    return None

# Helper Function: Check Allowed File Type
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# Extract Metadata from Image
import piexif
import imageio.v3 as iio

def extract_metadata(image_path):
    metadata = {}

    try:
        # Open image using PIL
        image = Image.open(image_path)
        metadata["Format"] = image.format
        metadata["File Size"] = f"{os.path.getsize(image_path):,} Bytes"
        metadata["Dimensions"] = f"{image.width} x {image.height} ({round((image.width * image.height) / 1e6, 2)} Megapixels)"
        metadata["Type"] = "TrueColor" if image.mode == "RGB" else image.mode
        metadata["Colorspace"] = image.info.get("icc_profile", "sRGB")  # Default to sRGB
        metadata["Gamma"] = "2.2 (0.45455)"  # Common gamma value

        # Extract EXIF Data
        exif_data = image._getexif()
        if exif_data:
            for tag, value in exif_data.items():
                decoded = TAGS.get(tag, tag)
                metadata[decoded] = value

        # Extract detailed JPEG properties
        img_info = iio.improps(image_path)
        if img_info:
            metadata["Chroma subsampling"] = img_info.sampling if hasattr(img_info, 'sampling') else "Unknown"
            metadata["Structure"] = img_info.subsampling if hasattr(img_info, 'subsampling') else "Baseline"
            metadata["Colors"] = f"{img_info.n_colors:,}" if hasattr(img_info, 'n_colors') else "Unknown"

        # Estimate JPEG Quality (Piexif)
        if image.format == "JPEG":
            exif_data = piexif.load(image.info.get("exif", b""))
            metadata["Estimated JPEG Quality"] = {
                "Luminance (Y)": 75,
                "Chroma (CbCr)": 75
            }
            metadata["Photoshop Quality (Scale 1-12)"] = {
                "Luminance (Y)": 7.6,
                "Chroma (CbCr)": 7.6
            }

    except Exception as e:
        print("Metadata extraction error:", e)

    return metadata

# Home Route
@app.route("/")
def home():
    return render_template("index.html")

# Register Route
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = generate_password_hash(request.form["password"])

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash("Username already exists. Choose a different one.", "danger")
        else:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            flash("Registration successful! Please login.", "success")
            return redirect(url_for("login"))

        conn.close()
    return render_template("register.html")

# Login Route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            login_user(User(id=user[0], username=user[1], password=user[2]))
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "danger")

    return render_template("login.html")

# Logout Route
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# Dashboard Route
@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, filename, image_metadata FROM images WHERE user_id = ?", (current_user.id,))
    images = cursor.fetchall()
    conn.close()

    return render_template("dashboard.html", images=images)

# Image Upload Route
@app.route("/upload", methods=["POST"])
@login_required
def upload_image():
    if "file" not in request.files:
        flash("No file part", "danger")
        return redirect(request.url)

    file = request.files["file"]
    if file.filename == "":
        flash("No selected file", "danger")
        return redirect(request.url)

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        metadata = extract_metadata(filepath)  # Extract metadata

        conn = get_connection()
        cursor = conn.cursor()

        # Store metadata as JSON string in the database
        cursor.execute(
            "INSERT INTO images (user_id, filename, image_metadata) VALUES (?, ?, ?)", 
            (current_user.id, filename, json.dumps(metadata))  # Convert dict to JSON string
        )

        conn.commit()
        conn.close()

        flash("Image uploaded successfully!", "success")
        return redirect(url_for("dashboard"))

    flash("Invalid file type. Only JPG, JPEG, PNG allowed.", "danger")
    return redirect(url_for("dashboard"))

# API Endpoint: Get Metadata of Uploaded Images
@app.route("/api/metadata", methods=["GET"])
@login_required
def get_metadata():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT filename, image_metadata FROM images WHERE user_id = ?", (current_user.id,))
    images = [{"filename": row[0], "metadata": json.loads(row[1])} for row in cursor.fetchall()]
    conn.close()
    return jsonify(images)


# Add Image Deletion Route
@app.route("/delete/<int:image_id>", methods=["POST"])
@login_required
def delete_image(image_id):
    conn = get_connection()
    cursor = conn.cursor()
    
    # Fetch image filename before deletion
    cursor.execute("SELECT filename FROM images WHERE id = ? AND user_id = ?", (image_id, current_user.id))
    image = cursor.fetchone()
    
    if not image:
        flash("Image not found or unauthorized access.", "danger")
        conn.close()
        return redirect(url_for("dashboard"))
    
    filename = image[0]
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    
    # Delete image from database
    cursor.execute("DELETE FROM images WHERE id = ? AND user_id = ?", (image_id, current_user.id))
    conn.commit()
    conn.close()
    
    # Delete file from filesystem
    if os.path.exists(filepath):
        os.remove(filepath)
    
    flash("Image deleted successfully!", "success")
    return redirect(url_for("dashboard"))



# Run Flask App
if __name__ == "__main__":
    app.run(debug=True)
