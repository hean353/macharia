import os
import secrets
from datetime import datetime, timedelta
import pymongo
import random
import string
from pymongo import MongoClient
import requests
from flask import Flask, render_template, request, redirect, session, url_for, jsonify, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask import url_for

def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
        return email
    except Exception:
        return False

# Configuration
MONGO_URI = "mongodb+srv://iconichean:EDrWdX9G3pPeLll1@cluster0.n3rva.mongodb.net/"
FLASK_SECRET_KEY = "your_secure_flask_secret_key"
PAYSTACK_PUBLIC_KEY = "pk_live_4844d97cb41c83140c5826cac03264051c0379d9"
PAYSTACK_SECRET_KEY = "sk_live_a33630e17b9047af3a5f26038a7dfffc58d01de1"
SECURITY_PASSWORD_SALT = 'your-salt'

# Validate configuration
if not MONGO_URI:
    raise ValueError("MONGO_URI is missing.")
if not PAYSTACK_PUBLIC_KEY or not PAYSTACK_SECRET_KEY:
    raise ValueError("Paystack keys are missing.")

# Connect to MongoDB
try:
    client = MongoClient(MONGO_URI)
    db = client["investment_app"]
    users_collection = db["users"]
except pymongo.errors.ConnectionFailure as e:
    print(f"MongoDB Connection Error: {e}")
    exit(1)

# Flask App Configuration
app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY
app.config['SECURITY_PASSWORD_SALT'] = SECURITY_PASSWORD_SALT
# File Upload Configuration
UPLOAD_FOLDER = os.path.abspath("static/uploads/")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Replace your current mail config with this:
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='socialboost254@gmail.com',  # Your full Gmail address
    MAIL_PASSWORD='ilku dvhf ewnj hctw',     # 16-digit app password (see below how to get this)
    MAIL_DEFAULT_SENDER=('Bigwinners', 'socialboost254@gmail.com')
)
mail = Mail(app)
### Routes ###

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        required_fields = ["fullname", "email", "username", "phone", "country", "password"]
        data = {key: request.form.get(key) for key in required_fields}

        # Check if any of the fields are missing
        if not all(data.values()):
            flash("Please fill in all required fields.", "danger")
            return redirect(url_for("home"))  # Redirect to home which has the registration form

        # Check for existing user (keep your existing checks)
        existing_user = users_collection.find_one({"email": data["email"]})
        existing_username = users_collection.find_one({"username": data["username"]})
        existing_phone = users_collection.find_one({"phone": data["phone"]})

        if existing_user:
            flash("Email already in use. Please choose a different email.", "danger")
            return redirect(url_for("home"))
        elif existing_username:
            flash("Username already in use. Please choose a different username.", "danger")
            return redirect(url_for("home"))
        elif existing_phone:
            flash("Phone number already in use. Please choose a different phone number.", "danger")
            return redirect(url_for("home"))

        # Hash password and save user
        data["password"] = generate_password_hash(data["password"])
        data["profile_picture"] = "default.jpg"
        users_collection.insert_one(data)

        # Set session data
        session["user_email"] = data["email"]
        session["user"] = data["username"]
        session["profile_picture"] = data["profile_picture"]
        session["user_id"] = str(data["_id"])  # Convert ObjectId to string

        flash("Registration successful! Welcome to your dashboard.", "success")
        return redirect(url_for("dashboard"))  # Redirect to dashboard

    return redirect(url_for("home"))  # GET requests go to home



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not email or not password:
            return jsonify({"error": "Missing email or password"}), 400

        user = users_collection.find_one({"email": email})
        if user and check_password_hash(user["password"], password):
            session.update({
                "user_id": str(user["_id"]),
                "user": user["username"],
                "user_email": email,
                "profile_picture": user.get("profile_picture", "default.jpg"),
            })
            return redirect(url_for("dashboard"))  # Directly redirect to dashboard

        return jsonify({"error": "Invalid credentials!"}), 401

    return render_template("login.html")


@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        if not email:
            flash("Email is required", "error")
            return redirect(url_for("forgot_password"))

        user = users_collection.find_one({"email": email})
        if not user:
            # Security: Don't reveal if user exists
            flash("This email does not exist.", "info")
            return redirect(url_for("forgot_password"))

        # Generate token (expires in 1 hour)
        token = generate_reset_token(email)
        reset_url = url_for('reset_password', token=token, _external=True)

        try:
            msg = Message(
                "Password Reset Request",
                recipients=[email],
                sender=app.config["MAIL_DEFAULT_SENDER"]
            )
            
            # Plain text version
            msg.body = f"""Click the link to reset your password:
{reset_url}

If you didn't request this, please ignore this email."""
            
            # HTML version with button
            msg.html = f"""
            <h2>Password Reset Request</h2>
            <p>Click the button below to reset your password:</p>
            <a href="{reset_url}" style="
                background-color: #4CAF50;
                color: white;
                padding: 10px 20px;
                text-decoration: none;
                border-radius: 5px;
                display: inline-block;
            ">Reset Password</a>
            <p>Or copy this link: {reset_url}</p>
            <p><em>This link expires in 1 hour.</em></p>
            """
            
            mail.send(msg)
            flash("Password reset link has been sent to your email", "success")
            return redirect(url_for("forgot_password"))
        
        except Exception as e:
            print(f"Email error: {str(e)}")
            flash("Failed to send reset link. Please try again later.", "error")
            return redirect(url_for("forgot_password"))
    
    return render_template("forgot_password.html")

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    # Verify token
    email = verify_reset_token(token)
    if not email:
        flash("Invalid or expired reset link", "error")
        return redirect(url_for("forgot_password"))

    user = users_collection.find_one({"email": email})
    if not user:
        flash("User not found", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if not new_password or new_password != confirm_password:
            flash("Passwords don't match", "error")
            return redirect(url_for("reset_password", token=token))

        # Update password and clear token
        hashed_password = generate_password_hash(new_password)
        users_collection.update_one(
            {"email": email},
            {"$set": {"password": hashed_password}}
        )
        
        flash("Password updated successfully! Please login", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)
@app.route("/dashboard")
def dashboard():
    if "user_email" not in session:
        return redirect(url_for("login"))

    user = users_collection.find_one({"email": session["user_email"]})
    if not user:
        session.clear()
        return redirect(url_for("login"))

    # Update session data with any new information
    session.update({
        "user": user.get("username", "User"),
        "investment": f"${user.get('initial_investment', 0):.2f} invested" if user.get('initial_investment') else "No active investment",
        "total_investment": f"${user.get('initial_investment', 0):.2f}" if user.get('initial_investment') else "$0",
        "profile_picture": user.get("profile_picture", "default.jpg"),
        "user_id": str(user["_id"])  # Ensure user_id is in session
    })

    return render_template("dashboard.html", session=session)
@app.route("/forex_data")
def forex_data():
    return jsonify({"forex_url": "https://fxpricing.com/fx-widget/market-currency-rates-widget.php?id=1,2,3,5,14,20"})

@app.route("/invest")
def invest():
    if "user_email" not in session:
        return redirect(url_for("login"))

    error = request.args.get('error')
    if error:
        flash(error, 'error')
    
    return render_template("invest.html")

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

    users_collection.update_one(
        {"email": session["user_email"]}, 
        {"$set": {"profile_picture": filename}}
    )
    session["profile_picture"] = filename

    flash("Profile picture updated!", "success")
    return redirect(url_for("account_settings"))

@app.route("/remove-profile-picture", methods=["POST"])
def remove_profile_picture():
    if "user_email" not in session:
        return jsonify({"error": "User not logged in!"}), 401

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], session["user_email"] + ".jpg")
    if os.path.exists(file_path):
        os.remove(file_path)

    users_collection.update_one(
        {"email": session["user_email"]}, 
        {"$set": {"profile_picture": "default.jpg"}}
    )
    session["profile_picture"] = "default.jpg"

    flash("Profile picture removed successfully!", "success")
    return redirect(url_for("account_settings"))

@app.route("/convert_currency", methods=["GET"])
def convert_currency():
    amount = request.args.get("amount")
    from_currency = request.args.get("from")
    to_currency = request.args.get("to")

    if not amount or not from_currency or not to_currency:
        return jsonify({"error": "Missing required parameters"}), 400

    try:
        response = requests.get(f"https://api.exchangerate-api.com/v4/latest/{from_currency}")
        response.raise_for_status()
        rate = response.json()["rates"].get(to_currency)

        if not rate:
            return jsonify({"error": "Invalid currency selected"}), 400

        return jsonify({
            "converted": round(float(amount) * rate, 2), 
            "rate": rate
        }), 200
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to fetch exchange rates: {str(e)}"}), 500

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

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
    if "user_email" not in session:
        return jsonify({"status": False, "message": "User not logged in"}), 401

    try:
        data = request.get_json()
        amount_kes = float(data.get("amount"))
        plan = data.get("plan", "unknown")

        if not amount_kes:
            return jsonify({"status": False, "message": "Missing amount"}), 400

        # Convert KES to USD for metadata
        conversion_response = requests.get(
            f"http://{request.host}/convert_currency?amount={amount_kes}&from=KES&to=USD"
        )
        conversion_data = conversion_response.json()
        
        if "error" in conversion_data:
            return jsonify({"status": False, "message": conversion_data["error"]}), 400
            
        amount_usd = conversion_data["converted"]

        headers = {
            "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json"
        }

        payload = {
            "email": session["user_email"],
            "amount": int(amount_kes * 100),
            "currency": "KES",
            "callback_url": url_for('paystack_callback', _external=True),
            "metadata": {
                "plan": plan,
                "amount_usd": amount_usd,
                "user_id": session.get("user_id")
            }
        }

        response = requests.post(
            "https://api.paystack.co/transaction/initialize",
            headers=headers,
            json=payload
        )
        response_data = response.json()

        if response_data.get("status"):
            return jsonify(response_data)
        return jsonify({
            "status": False, 
            "message": response_data.get("message", "Payment initialization failed")
        }), 400

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
            metadata = data["data"].get("metadata", {})
            user_id = metadata.get("user_id")
            
            if not user_id:
                flash("User identification missing in payment", "error")
                return redirect(url_for("invest"))

            amount_usd = metadata.get("amount_usd", 0)
            
            # Update user investment
            users_collection.update_one(
                {"_id": user_id},
                {"$set": {
                    "initial_investment": amount_usd,
                    "investment_plan": metadata.get("plan", "unknown"),
                    "investment_time": datetime.utcnow(),
                    "investment_status": "active"
                }}
            )

            # Refresh session if current user
            if session.get("user_id") == user_id:
                session.update({
                    "investment": f"${amount_usd:.2f} invested",
                    "total_investment": f"${amount_usd:.2f}",
                    "investment_plan": metadata.get("plan", "unknown")
                })

            return redirect(url_for("dashboard", payment_success="true"))

        flash("Payment verification failed!", "error")
        return redirect(url_for("invest"))

    except Exception as e:
        flash(f"Payment processing error: {str(e)}", "error")
        return redirect(url_for("invest"))

@app.route("/account-settings", methods=["GET", "POST"])
def account_settings():
    if "user_email" not in session:
        return redirect(url_for("login"))

    user = users_collection.find_one({"email": session["user_email"]})
    if not user:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        # Handle form submissions
        pass

    return render_template("account_settings.html", session=session)

@app.route("/change-password", methods=["POST"])
def change_password():
    if "user_email" not in session:
        flash("User not logged in!", "error")
        return redirect(url_for("account_settings"))

    old_password = request.form.get("old_password")
    new_password = request.form.get("new_password")
    confirm_password = request.form.get("confirm_password")

    if not all([old_password, new_password, confirm_password]):
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
    users_collection.update_one(
        {"email": session["user_email"]}, 
        {"$set": {"password": hashed_password}}
    )

    flash("Password changed successfully!", "success")
    return redirect(url_for("account_settings"))

@app.route("/check_withdrawal", methods=["POST"])
def check_withdrawal():
    if "user_email" not in session:
        return jsonify({"error": "User not logged in!"}), 401

    user = users_collection.find_one({"email": session["user_email"]})
    
    if not user or "investment_time" not in user:
        return jsonify({"error": "No investment found!"}), 400

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
    
    initial_amount = float(user.get("initial_investment", 0))
    required_payment = initial_amount * 2
        
    return jsonify({
        "status": "ready",
        "message": f"Pay ${required_payment:.2f} to withdraw profits",
        "required_payment": required_payment,
        "can_withdraw": True
    }), 200

@app.route("/process_withdrawal", methods=["POST"])
def process_withdrawal():
    if "user_email" not in session:
        return jsonify({"error": "User not logged in!"}), 401

    try:
        user = users_collection.find_one({"email": session["user_email"]})
        
        if not user or "investment_time" not in user:
            return jsonify({"error": "No investment found!"}), 400

        investment_time = user["investment_time"]
        current_time = datetime.utcnow()
        maturity_time = investment_time + timedelta(hours=6)
        
        if current_time < maturity_time:
            return jsonify({"error": "Withdrawal not yet available!"}), 400

        initial_amount_usd = float(user.get("initial_investment", 0))
        required_payment_usd = initial_amount_usd * 2

        conversion_response = requests.get(
            f"http://{request.host}/convert_currency?amount={required_payment_usd}&from=USD&to=KES"
        )
        conversion_data = conversion_response.json()
        
        if "error" in conversion_data:
            return jsonify({"error": f"Currency conversion failed: {conversion_data['error']}"}), 400
            
        required_payment_kes = conversion_data["converted"]

        headers = {
            "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json"
        }

        payload = {
            "email": session["user_email"],
            "amount": int(required_payment_kes * 100),
            "currency": "KES",
            "callback_url": url_for('withdrawal_callback', _external=True),
            "metadata": {
                "purpose": "withdrawal_fee",
                "original_amount_usd": required_payment_usd,
                "plan": user.get("investment_plan", "unknown"),
                "is_withdrawal": True,
                "user_id": session.get("user_id")
            }
        }

        response = requests.post(
            "https://api.paystack.co/transaction/initialize",
            headers=headers,
            json=payload
        )
        response_data = response.json()

        if response_data.get("status"):
            return jsonify({
                "status": True,
                "message": "Payment initialized successfully",
                "data": response_data["data"]
            })
        return jsonify({
            "status": False,
            "message": response_data.get("message", "Payment initialization failed")
        }), 400

    except Exception as e:
        return jsonify({"error": f"Withdrawal processing failed: {str(e)}"}), 500

@app.route("/withdrawal_callback", methods=["GET"])
def withdrawal_callback():
    reference = request.args.get('reference')

    if not reference:
        flash("Withdrawal reference missing!", "error")
        return redirect(url_for("dashboard"))

    try:
        headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}
        response = requests.get(
            f"https://api.paystack.co/transaction/verify/{reference}",
            headers=headers
        )
        data = response.json()

        if data["status"] and data["data"]["status"] == "success":
            metadata = data["data"].get("metadata", {})
            user_id = metadata.get("user_id")
            
            if not user_id:
                flash("User identification missing in withdrawal", "error")
                return redirect(url_for("dashboard"))

            # Mark investment as completed
            users_collection.update_one(
                {"_id": user_id},
                {"$set": {
                    "investment_status": "completed",
                    "withdrawal_time": datetime.utcnow()
                }}
            )

            # Refresh session if current user
            if session.get("user_id") == user_id:
                session["investment_status"] = "completed"
                flash("Withdrawal processed successfully!", "success")

            return redirect(url_for("dashboard"))

        flash("Withdrawal verification failed!", "error")
        return redirect(url_for("dashboard"))

    except Exception as e:
        flash(f"Withdrawal processing error: {str(e)}", "error")
        return redirect(url_for("dashboard"))

@app.route("/api/investment_details", methods=["GET"])
def investment_details():
    if "user_email" not in session:
        return jsonify({"error": "User not logged in!"}), 401

    user = users_collection.find_one({"email": session["user_email"]})
    
    if not user or "initial_investment" not in user:
        return jsonify({
            "amount_invested": 0,
            "investment_status": "none"
        }), 200

    return jsonify({
        "amount_invested": float(user.get("initial_investment", 0)),
        "investment_status": user.get("investment_status", "none")
    }), 200

@app.route("/api/realtime_investment_data", methods=["GET"])
def realtime_investment_data():
    if "user_email" not in session:
        return jsonify({"error": "User not logged in!"}), 401

    user = users_collection.find_one({"email": session["user_email"]})
    
    if not user or "investment_time" not in user:
        return jsonify({
            "error": "No active investment found!",
            "timestamp": datetime.utcnow().isoformat(),
            "profit": 0,
            "initial_investment": 0,
            "investment_status": "none"
        }), 200

    investment_time = user["investment_time"]
    initial_investment = float(user.get("initial_investment", 0))
    current_time = datetime.utcnow()
    maturity_time = investment_time + timedelta(hours=6)

    elapsed_time = current_time - investment_time
    time_progress = min(max(elapsed_time.total_seconds() / (6 * 3600), 0), 1)

    profit = initial_investment * 5 * time_progress
    time_remaining = max((maturity_time - current_time).total_seconds(), 0)
    hours_remaining = int(time_remaining // 3600)
    minutes_remaining = int((time_remaining % 3600) // 60)

    return jsonify({
        "timestamp": current_time.isoformat(),
        "profit": round(profit, 2),
        "initial_investment": round(initial_investment, 2),
        "time_progress": round(time_progress * 100, 2),
        "hours_remaining": hours_remaining,
        "minutes_remaining": minutes_remaining,
        "investment_status": user.get("investment_status", "active"),
        "maturity_time": maturity_time.isoformat()
    }), 200

if __name__ == "__main__":
    app.run(debug=True)