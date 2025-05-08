import os
import pymongo
import requests
from flask import Flask, render_template, request, redirect, session, url_for, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
# Hardcoded Configuration (Directly inside the script)
MONGO_URI = "mongodb+srv://iconichean:EDrWdX9G3pPeLll1@cluster0.n3rva.mongodb.net/"
FLASK_SECRET_KEY = "your_secure_flask_secret_key"
PAYSTACK_PUBLIC_KEY = "pk_live_4844d97cb41c83140c5826cac03264051c0379d9"
PAYSTACK_SECRET_KEY = "sk_live_a33630e17b9047af3a5f26038a7dfffc58d01de1"

# Validate environment variables
if not MONGO_URI:
    raise ValueError("MONGO_URI is missing.")
if not PAYSTACK_PUBLIC_KEY or not PAYSTACK_SECRET_KEY:
    raise ValueError("Paystack keys are missing.")

# Connect to MongoDB with error handling
try:
    client = pymongo.MongoClient(MONGO_URI)
    db = client["investment_app"]
    users_collection = db["users"]
except pymongo.errors.ConnectionFailure as e:
    print(f"MongoDB Connection Error: {e}")
    exit(1)

# Flask App Configuration
app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

UPLOAD_FOLDER = os.path.abspath("static/uploads/")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

### ✅ Home Route
@app.route("/")
def home():
    return render_template("index.html")

### ✅ User Registration
@app.route("/register", methods=["POST"])
def register():
    required_fields = ["fullname", "email", "username", "phone", "country", "password"]
    data = {key: request.form.get(key) for key in required_fields}

    if not all(data.values()):
        return jsonify({"error": "Missing required fields"}), 400

    if users_collection.find_one({"email": data["email"]}) or users_collection.find_one({"username": data["username"]}):
        return jsonify({"error": "User already exists!"}), 409

    data["password"] = generate_password_hash(data["password"])
    data["profile_picture"] = "default.jpg"
    users_collection.insert_one(data)

    return jsonify({"success": "User registered successfully!"}), 201

### ✅ User Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email, password = request.form.get("email"), request.form.get("password")

        if not email or not password:
            return jsonify({"error": "Missing email or password"}), 400

        user = users_collection.find_one({"email": email})
        if user and check_password_hash(user["password"], password):
            session.update({
                "user": user["username"],
                "user_email": email,
                "profile_picture": user.get("profile_picture", "default.jpg"),
            })
            return redirect(url_for("dashboard"))

        return jsonify({"error": "Invalid credentials!"}), 401

    return render_template("login.html")

### ✅ Dashboard Route
@app.route("/dashboard")
def dashboard():
    if "user_email" in session:
        user = users_collection.find_one({"email": session["user_email"]})
        session["investment"] = user.get("investment", "No active investment")

    return render_template("dashboard.html", session=session)





### ✅ Fetch Live Forex Data
@app.route("/forex_data")
def forex_data():
    return jsonify({"forex_url": "https://fxpricing.com/fx-widget/market-currency-rates-widget.php?id=1,2,3,5,14,20"})

### ✅ Investment Page
@app.route("/invest")
def invest():
    return render_template("invest.html") if "user" in session else redirect(url_for("login"))

### ✅ Upload Profile Picture
@app.route("/upload-profile-picture", methods=["POST"])
def upload_profile_picture():
    if "user_email" not in session:
        return jsonify({"error": "User not logged in!"}), 401

    file = request.files.get("profile_pic")
    if not file:
        return jsonify({"error": "No file uploaded!"}), 400

    filename = secure_filename(session["user_email"] + ".jpg")
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(file_path)

    users_collection.update_one({"email": session["user_email"]}, {"$set": {"profile_picture": filename}})
    session["profile_picture"] = filename

    return jsonify({"success": "Profile picture updated!", "image_url": url_for("static", filename=f"uploads/{filename}")}), 200

### ✅ Remove Profile Picture
@app.route("/remove-profile-picture", methods=["POST"])
def remove_profile_picture():
    if "user_email" not in session:
        return jsonify({"error": "User not logged in!"}), 401

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], session["user_email"] + ".jpg")
    if os.path.exists(file_path):
        os.remove(file_path)

    users_collection.update_one({"email": session["user_email"]}, {"$set": {"profile_picture": "default.jpg"}})
    session["profile_picture"] = "default.jpg"

    return jsonify({"success": "Profile picture removed!"}), 200

### ✅ Currency Conversion API
@app.route("/convert_currency", methods=["GET"])
def convert_currency():
    amount, from_currency, to_currency = request.args.get("amount"), request.args.get("from"), request.args.get("to")

    if not amount or not from_currency or not to_currency:
        return jsonify({"error": "Missing required parameters"}), 400

    try:
        response = requests.get(f"https://api.exchangerate-api.com/v4/latest/{from_currency}")
        response.raise_for_status()
        rate = response.json()["rates"].get(to_currency)

        if not rate:
            return jsonify({"error": "Invalid currency selected"}), 400

        return jsonify({"converted": round(float(amount) * rate, 2), "rate": rate}), 200
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to fetch exchange rates: {str(e)}"}), 500

### ✅ User Logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

### ✅ Terms and Conditions Page
@app.route("/terms")
def terms():
    return render_template("terms.html")
@app.route("/initialize_transaction", methods=["POST"])
def initialize_transaction():
    data = request.json
    email = data.get("email")
    amount_kes = data.get("amount")

    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "email": email,
        "amount": int(amount_kes * 100),  # Convert KES to kobo format
        "currency": "KES",
        "callback_url": url_for('paystack_callback', _external=True)  # Redirect after payment
    }

    response = requests.post("https://api.paystack.co/transaction/initialize", headers=headers, json=payload)
    
    # Store investment timestamp in database
    if response.json()["status"]:
        users_collection.update_one({"email": email}, {
            "$set": {
                "investment": amount_kes,
                "investment_time": datetime.utcnow()  # Track time of investment
            }
        })

    return jsonify(response.json())  # Send Paystack response to frontend
@app.route("/withdraw", methods=["POST"])
def withdraw():
    if "user_email" not in session:
        return jsonify({"error": "User not logged in!"}), 401

    user = users_collection.find_one({"email": session["user_email"]})

    if not user or "investment_time" not in user:
        return jsonify({"error": "No active investment!"}), 400

    # Check if 6 hours have passed
    investment_time = user["investment_time"]
    current_time = datetime.utcnow()
    time_diff = current_time - investment_time

    if time_diff < timedelta(hours=6):
        remaining_time = (timedelta(hours=6) - time_diff).seconds // 3600
        return jsonify({"error": f"Investment not matured! Wait {remaining_time} hours."}), 403

    # Calculate payout amount
    initial_amount = user["investment"]
    profit_amount = initial_amount * 2  # 200% profit
    required_payment = initial_amount * 2  # User must pay 200% of initial investment

    return jsonify({
        "success": True,
        "message": f"To receive {profit_amount}, you must pay {required_payment} first.",
        "required_payment": required_payment
    })

@app.route('/paystack_callback', methods=['GET'])
def paystack_callback():
    reference = request.args.get('reference')

    if not reference:
        return "Payment reference missing!", 400

    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}
    response = requests.get(f"https://api.paystack.co/transaction/verify/{reference}", headers=headers)
    data = response.json()

    if data["status"] and data["data"]["status"] == "success":
        user_email = data["data"]["customer"]["email"]
        amount_paid = data["data"]["amount"] / 100  # Convert kobo to currency
        
        # Update investment status in MongoDB
        users_collection.update_one({"email": user_email}, {"$set": {"investment": f"${amount_paid} invested"}})

        # Refresh session so the dashboard reflects changes
        session["investment"] = f"${amount_paid} invested"

        return redirect(url_for("dashboard"))  # Redirect back to dashboard

    return "Payment verification failed!", 400



if __name__ == "__main__":
    app.run(debug=True)
