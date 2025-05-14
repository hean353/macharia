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
from bson import ObjectId

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
PAYSTACK_PUBLIC_KEY = "pk_live_c4739380828ad87d3280946a60cf07fc965ab8af"
PAYSTACK_SECRET_KEY = "sk_live_70256e6f370946e04e3b93ad7c8b4537a3514b1e"
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
    MAIL_USERNAME='winnersb27@gmail.com',  # Your full Gmail address
    MAIL_PASSWORD='dutu tkvw gynk qebe',     # 16-digit app password (see below how to get this)
    MAIL_DEFAULT_SENDER=('Big Winners', 'winnersb27@gmail.com')
)
mail = Mail(app)
# Helper Functions
def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(app.secret_key)
    return serializer.dumps(email, salt=app.config["SECURITY_PASSWORD_SALT"])


def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.secret_key)
    try:
        email = serializer.loads(token, salt=app.config["SECURITY_PASSWORD_SALT"], max_age=expiration)
        return email
    except Exception:
        return False

@app.route("/")
def welcome():
    return render_template("welcome.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            # Collect user input
            required_fields = ["fullname", "email", "username", "phone", "country", "password", "security_question", "security_answer", "gender"]
            data = {key: request.form.get(key) for key in required_fields}

            # Check for missing fields
            if not all(data.values()):
                flash("Please fill in all required fields.", "danger")
                return redirect(url_for("register"))

            # Check for duplicate entries in MongoDB
            if users_collection.find_one({"email": data["email"]}):
                flash("Email already in use. Please choose a different email.", "danger")
                return redirect(url_for("register"))
            if users_collection.find_one({"username": data["username"]}):
                flash("Username already in use. Please choose a different username.", "danger")
                return redirect(url_for("register"))
            if users_collection.find_one({"phone": data["phone"]}):
                flash("Phone number already in use. Please choose a different phone number.", "danger")
                return redirect(url_for("register"))

            # Hash the password
            data["password"] = generate_password_hash(data["password"], method="scrypt")

            # Add default fields
            data["profile_picture"] = "default.jpg"
            data["initial_investment"] = 0.0
            data["investment_time"] = None
            data["investment_status"] = "none"

            # Insert the user into MongoDB
            result = users_collection.insert_one(data)

            # Update the session
            session.update({
                "user_email": data["email"],
                "user": data["username"],
                "profile_picture": data["profile_picture"],
                "user_id": str(result.inserted_id),
            })

            flash("Registration successful! Welcome to your dashboard.", "success")
            return redirect(url_for("dashboard"))
        except Exception as e:
            # Log the exact error for debugging
            print(f"Error during registration: {e}")
            flash("An error occurred during registration. Please try again later.", "danger")
            return redirect(url_for("register"))

    # Render the registration page (index.html) for GET requests
    return render_template("index.html")
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        try:
            email = request.form.get("email")
            password = request.form.get("password")

            if not email or not password:
                flash("Email and password are required.", "danger")
                return redirect(url_for("login"))

            # Find the user by email
            user = users_collection.find_one({"email": email})
            if user and check_password_hash(user["password"], password):
                session.update({
                    "user_id": str(user["_id"]),
                    "user": user["username"],
                    "user_email": email,
                    "profile_picture": user.get("profile_picture", "default.jpg"),
                })
                return redirect(url_for("dashboard"))

            flash("Invalid email or password.", "danger")
            return redirect(url_for("login"))
        except Exception as e:
            print(f"Error during login: {e}")
            flash("An error occurred during login. Please try again later.", "danger")
            return redirect(url_for("login"))
    return render_template("login.html")
@app.route("/index")
def index():
    return render_template("index.html")


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

    # Calculate investment progress
    investment_status = user.get("investment_status", "none")
    time_progress, time_remaining = 0, "0h 0m"

    if investment_status == "active" and user.get("investment_time"):
        investment_time = user["investment_time"]
        current_time = datetime.utcnow()
        maturity_time = investment_time + timedelta(hours=6)
        elapsed_time = (current_time - investment_time).total_seconds()
        total_duration = timedelta(hours=6).total_seconds()
        time_progress = min(max(elapsed_time / total_duration, 0), 1)
        time_left = max(maturity_time - current_time, timedelta(0))
        hours, minutes = divmod(time_left.seconds, 3600)
        time_remaining = f"{hours}h {minutes}m"

    initial_investment = float(user.get("initial_investment", 0))
    session.update(
        {
            "investment": f"${initial_investment:.2f} invested" if initial_investment > 0 else "No active investment",
            "total_investment": f"${initial_investment:.2f}",
            "investment_status": investment_status,
            "time_progress": round(time_progress * 100, 1),
            "time_remaining": time_remaining,
        }
    )
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
    return redirect(url_for("welcome"))

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
        print(f"Paystack verification response: {data}")

        if data["status"] and data["data"]["status"] == "success":
            metadata = data["data"].get("metadata", {})
            user_id = metadata.get("user_id")
            
            if not user_id:
                flash("User identification missing in payment", "error")
                return redirect(url_for("dashboard"))

            # Validate ObjectId
            try:
                user_id_obj = ObjectId(user_id)
            except Exception as e:
                print(f"Invalid ObjectId: {user_id}, Error: {e}")
                flash("Invalid user ID", "error")
                return redirect(url_for("dashboard"))

            # Proceed with updates
            amount_usd = float(metadata.get("amount_usd", 0))
            investment_time = datetime.utcnow()
            update_data = {
                "initial_investment": amount_usd,
                "investment_time": investment_time,
                "investment_status": "active"
            }

            # Update MongoDB
            result = users_collection.update_one(
                {"_id": user_id_obj},  # Use the validated ObjectId
                {"$set": update_data}
            )
            print(f"Updated user {user_id} with: {update_data}")

            if result.modified_count == 0:
                print("Warning: No document was updated. Check the user ID.")

            # Update session if the current user matches
            if session.get("user_id") == user_id:
                session.update({
                    "investment": f"${amount_usd:.2f} invested",
                    "total_investment": f"${amount_usd:.2f}",
                    "investment_status": "active"
                })

            flash("Payment successful! Your investment is now active.", "success")
            return redirect(url_for("dashboard"))

        flash("Payment verification failed!", "error")
        return redirect(url_for("dashboard"))

    except Exception as e:
        print(f"Error in paystack_callback: {e}")
        flash("Payment processing error.", "error")
        return redirect(url_for("dashboard"))
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
    print(f"Fetched user data for /api/investment_details: {user}")  # Add this log

    if not user:
        return jsonify({
            "amount_invested": 0.0,
            "investment_status": "none"
        }), 200

    return jsonify({
        "amount_invested": float(user.get("initial_investment", 0.0)),
        "investment_status": user.get("investment_status", "none")
    }), 200

@app.route("/api/realtime_investment_data", methods=["GET"])
def realtime_investment_data():
    if "user_email" not in session:
        return jsonify({"error": "User not logged in!"}), 401

    user = users_collection.find_one({"email": session["user_email"]})
    print(f"Fetched user data for /api/realtime_investment_data: {user}")  # Add this log

    if not user:
        return jsonify({
            "error": "User not found",
            "profit": 0.0,
            "initial_investment": 0.0,
            "current_value": 0.0,
            "time_progress": 0.0,
            "hours_remaining": 0,
            "minutes_remaining": 0,
            "investment_status": "none"
        }), 200

    # Handle missing investment_time
    investment_time = user.get("investment_time")
    if not investment_time:
        return jsonify({
            "profit": 0.0,
            "initial_investment": float(user.get("initial_investment", 0.0)),
            "current_value": 0.0,
            "time_progress": 0.0,
            "hours_remaining": 0,
            "minutes_remaining": 0,
            "investment_status": user.get("investment_status", "none")
        }), 200

    try:
        # Calculate investment progress
        investment_time = user["investment_time"]
        initial_investment = float(user.get("initial_investment", 0.0))
        current_time = datetime.utcnow()
        maturity_time = investment_time + timedelta(hours=6)

        elapsed_time = (current_time - investment_time).total_seconds()
        total_duration = timedelta(hours=6).total_seconds()
        time_progress = min(max(elapsed_time / total_duration, 0), 1)

        current_value = initial_investment * (1 + 4 * time_progress)
        profit = current_value - initial_investment

        hours_remaining = max(int((maturity_time - current_time).total_seconds() // 3600), 0)
        minutes_remaining = max(int(((maturity_time - current_time).total_seconds() % 3600) // 60), 0)

        print(f"Calculated data: profit={profit}, current_value={current_value}, time_progress={time_progress}")  # Add this log

        return jsonify({
            "profit": round(profit, 2),
            "initial_investment": round(initial_investment, 2),
            "current_value": round(current_value, 2),
            "time_progress": round(time_progress * 100, 2),
            "hours_remaining": hours_remaining,
            "minutes_remaining": minutes_remaining,
            "investment_status": user.get("investment_status", "active")
        }), 200
    except Exception as e:
        print(f"Error in /api/realtime_investment_data: {e}")
        return jsonify({"error": "Failed to fetch investment data"}), 500
    
if __name__ == "__main__":
    app.run(debug=True)
