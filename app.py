import os
import pymongo
import requests
from flask import Flask, render_template, request, redirect, session, url_for, jsonify, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

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
        if user and "initial_investment" in user:
            session["investment"] = f"${user['initial_investment']:.2f} invested"
    
    # Handle flash messages from AJAX calls
    error = request.args.get('error')
    if error:
        flash(error, 'error')
        
    info = request.args.get('info')
    if info:
        flash(info, 'info')
    
    return render_template("dashboard.html", session=session)





### ✅ Fetch Live Forex Data
@app.route("/forex_data")
def forex_data():
    return jsonify({"forex_url": "https://fxpricing.com/fx-widget/market-currency-rates-widget.php?id=1,2,3,5,14,20"})

### ✅ Investment Page
@app.route("/invest")
def invest():
    # Handle error messages from AJAX calls
    error = request.args.get('error')
    if error:
        flash(error, 'error')
    
    return render_template("invest.html") if "user" in session else redirect(url_for("login"))

### ✅ Upload Profile Picture
@app.route("/upload-profile-picture", methods=["POST"])
def upload_profile_picture():
    if "user_email" not in session:
        flash("User not logged in!", "error")
        return redirect(url_for("account_settings"))

    file = request.files.get("profile_pic")
    if not file:
        flash("No file uploaded!", "error")
        return redirect(url_for("account_settings"))

    filename = secure_filename(session["user_email"] + ".jpg")
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(file_path)

    users_collection.update_one({"email": session["user_email"]}, {"$set": {"profile_picture": filename}})
    session["profile_picture"] = filename

    flash("Profile picture updated!", "success")
    return redirect(url_for("account_settings"))

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

    flash("Profile picture removed successfully!","success")
    return redirect(url_for("account_settings"))

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
@app.route("/about")
def about():
    return render_template("about.html")
@app.route("/privacy")
def privacy():
    return render_template("privacy.html")
@app.route("/contact")
def contact():
    return render_template("contact.html")
@app.route("/initialize_transaction", methods=["POST"])
def initialize_transaction():
    try:
        data = request.get_json()
        email = data.get("email")
        amount_kes = float(data.get("amount"))
        plan = data.get("plan", "unknown")

        if not email or not amount_kes:
            return jsonify({"status": False, "message": "Missing required parameters"}), 400

        # Convert KES to USD for storage
        conversion_response = requests.get(
            f"http://{request.host}/convert_currency?amount={amount_kes}&from=KES&to=USD"
        )
        conversion_data = conversion_response.json()
        
        if "error" in conversion_data:
            return jsonify({"status": False, "message": conversion_data["error"]}), 400
            
        amount_usd = conversion_data["converted"]

        # Initialize Paystack payment
        headers = {
            "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json"
        }

        payload = {
            "email": email,
            "amount": int(amount_kes * 100),  # Convert to kobo
            "currency": "KES",
            "callback_url": url_for('paystack_callback', _external=True),
            "metadata": {
                "plan": plan,
                "amount_usd": amount_usd
            }
        }

        response = requests.post(
            "https://api.paystack.co/transaction/initialize",
            headers=headers,
            json=payload
        )
        response_data = response.json()

        if response_data.get("status"):
            # Store investment details
            users_collection.update_one(
                {"email": email},
                {"$set": {
                    "investment_time": datetime.utcnow(),
                    "initial_investment": amount_usd,
                    "investment_plan": plan,
                    "investment_status": "pending"
                }},
                upsert=True
            )
            return jsonify(response_data)
        else:
            return jsonify({"status": False, "message": response_data.get("message", "Payment initialization failed")}), 400

    except Exception as e:
        return jsonify({"status": False, "message": str(e)}), 500
@app.route('/paystack_callback', methods=['GET'])
def paystack_callback():
    reference = request.args.get('reference')

    if not reference:
        flash("Payment reference missing!", "error")
        return redirect(url_for("invest"))

    try:
        headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}
        response = requests.get(
            f"https://api.paystack.co/transaction/verify/{reference}",
            headers=headers
        )
        data = response.json()

        if data["status"] and data["data"]["status"] == "success":
            user_email = data["data"]["customer"]["email"]
            amount_paid = data["data"]["amount"] / 100  # Convert kobo to KES
            metadata = data["data"].get("metadata", {})

            # Convert KES to USD for display
            conversion_response = requests.get(
                f"http://{request.host}/convert_currency?amount={amount_paid}&from=KES&to=USD"
            )
            conversion_data = conversion_response.json()
            amount_usd = conversion_data.get("converted", amount_paid / 100)  # Fallback rate

            # Update user investment
            users_collection.update_one(
                {"email": user_email},
                {"$set": {
                    "investment": f"${amount_usd:.2f} invested",
                    "investment_status": "active",
                    "initial_investment": amount_usd,
                    "investment_plan": metadata.get("plan", "unknown")
                }}
            )

            # Update session
            if session.get("user_email") == user_email:
                session["investment"] = f"${amount_usd:.2f} invested"

            flash("Payment successful! Your investment is now active.", "success")
            return redirect(url_for("dashboard"))

        flash("Payment verification failed!", "error")
        return redirect(url_for("invest"))

    except Exception as e:
        flash(f"Payment processing error: {str(e)}", "error")
        return redirect(url_for("invest"))
### ✅ Account Settings Page
@app.route("/account-settings", methods=["GET", "POST"])
def account_settings():
    if "user_email" not in session:
        return redirect(url_for("login"))

    # Fetch user data from the database
    user = users_collection.find_one({"email": session["user_email"]})

    if not user:
        return jsonify({"error": "User data not found!"}), 404

    # Update session data with user details
    session["user"] = user.get("username", "User")
    session["user_email"] = user.get("email", "")
    session["profile_picture"] = user.get("profile_picture", "default.jpg")

    # Render account settings page with session data
    return render_template("account_settings.html", session=session)

@app.route("/change-password", methods=["POST"])
def change_password():
    if "user_email" not in session:
        flash("User not logged in!", "error")
        return redirect(url_for("account_settings"))

    old_password = request.form.get("old_password")
    new_password = request.form.get("new_password")
    confirm_password = request.form.get("confirm_password")

    if not old_password or not new_password or not confirm_password:
        flash("All fields are required!", "error")
        return redirect(url_for("account_settings"))

    if new_password != confirm_password:
        flash("Passwords do not match!", "error")
        return redirect(url_for("account_settings"))

    user = users_collection.find_one({"email": session["user_email"]})

    if not user or not check_password_hash(user["password"], old_password):
        flash("Old password is incorrect!", "error")
        return redirect(url_for("account_settings"))

    hashed_password = generate_password_hash(new_password)
    users_collection.update_one({"email": session["user_email"]}, {"$set": {"password": hashed_password}})

    flash("Password changed successfully!", "success")
    return redirect(url_for("account_settings"))
# Add to your imports
from datetime import datetime, timedelta

# Add this new route for withdrawal checking
@app.route("/check_withdrawal", methods=["POST"])
def check_withdrawal():
    if "user_email" not in session:
        return jsonify({"error": "User not logged in!"}), 401

    user = users_collection.find_one({"email": session["user_email"]})
    
    if not user or "investment_time" not in user:
        return jsonify({"error": "No investment found!"}), 400

    # Calculate time remaining
    investment_time = user["investment_time"]
    current_time = datetime.utcnow()
    maturity_time = investment_time + timedelta(hours=6)
    time_remaining = maturity_time - current_time

    if current_time < maturity_time:
        hours = time_remaining.seconds // 3600
        minutes = (time_remaining.seconds % 3600) // 60
        return jsonify({
            "status": "pending",
            "message": f"Profits will mature in {hours}h {minutes}m",
            "can_withdraw": False
        }), 200
    else:
        # Calculate 200% of initial investment
        initial_amount = float(user.get("initial_investment", 0))
        required_payment = initial_amount * 2
        
        return jsonify({
            "status": "ready",
            "message": f"Pay ${required_payment:.2f} to withdraw profits",
            "required_payment": required_payment,
            "can_withdraw": True
        }), 200

# Add this new route for withdrawal payment
@app.route("/process_withdrawal", methods=["POST"])
def process_withdrawal():
    if "user_email" not in session:
        return jsonify({"error": "User not logged in!"}), 401

    try:
        user = users_collection.find_one({"email": session["user_email"]})
        
        if not user or "investment_time" not in user:
            return jsonify({"error": "No investment found!"}), 400

        # Verify 6 hours have passed
        investment_time = user["investment_time"]
        current_time = datetime.utcnow()
        maturity_time = investment_time + timedelta(hours=6)
        
        if current_time < maturity_time:
            return jsonify({"error": "Withdrawal not yet available!"}), 400

        # Calculate 200% of initial investment in USD
        initial_amount_usd = float(user.get("initial_investment", 0))
        required_payment_usd = initial_amount_usd * 2

        # Convert USD to KES for Paystack payment
        conversion_response = requests.get(
            f"/convert_currency?amount={required_payment_usd}&from=USD&to=KES"
        )
        conversion_data = conversion_response.json()
        
        if "error" in conversion_data:
            return jsonify({"error": f"Currency conversion failed: {conversion_data['error']}"}), 400
            
        required_payment_kes = conversion_data["converted"]

        # Initialize Paystack payment
        headers = {
            "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json"
        }

        payload = {
            "email": session["user_email"],
            "amount": int(required_payment_kes * 100),  # Convert to kobo
            "currency": "KES",
            "metadata": {
                "purpose": "withdrawal_fee",
                "original_amount_usd": required_payment_usd
            }
        }

        response = requests.post(
            "https://api.paystack.co/transaction/initialize",
            headers=headers,
            json=payload
        )
        
        return jsonify(response.json())

    except Exception as e:
        return jsonify({"error": f"Withdrawal processing failed: {str(e)}"}), 500
@app.route("/api/investment_details", methods=["GET"])
def investment_details():
    if "user_email" not in session:
        return jsonify({"error": "User not logged in!"}), 401

    user = users_collection.find_one({"email": session["user_email"]})
    
    if not user or "investment_time" not in user:
        return jsonify({
            "amount_invested": 0,
            "maturity_time": None,
            "start_time": None,
            "investment_status": "none"
        }), 200

    investment_time = user["investment_time"]
    maturity_time = investment_time + timedelta(hours=6)
    amount_invested = float(user.get("initial_investment", 0))
    current_time = datetime.utcnow()
    
    return jsonify({
        "amount_invested": amount_invested,
        "maturity_time": maturity_time.isoformat(),
        "start_time": investment_time.isoformat(),
        "current_time": current_time.isoformat(),
        "investment_status": "active" if current_time < maturity_time else "matured"
    }), 200
if __name__ == "__main__":
    app.run(debug=True)
