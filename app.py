from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from models import db, User
from forms import RegisterForm, LoginForm
from twilio.rest import Client
import os
import random
from dotenv import load_dotenv
from flask_mail import Mail,Message
import pyotp
import qrcode
import io
import base64
import secrets
from datetime import datetime, timedelta

app = Flask(__name__)
app.config["SECRET_KEY"] = "your_secret_key"  # Change this to a secure key
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"

db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'mfastudyncl@gmail.com'
app.config['MAIL_PASSWORD'] = 'ugke hqkv qtyq edwn'

mail = Mail(app)

load_dotenv()

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER")

client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Home Route
@app.route("/")
def home():
    return render_template("home.html")

# Register Route
@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Account created! You can now log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)

# Login Route
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid username or password", "danger")
    return render_template("login.html", form=form)

# Dashboard Route (Requires Login)
@app.route("/dashboard")
@login_required
def dashboard():
    return f"<h1>Welcome {current_user.username}! You are logged in.</h1><a href='/logout'>Logout</a>"

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "info")
    return redirect(url_for("login"))

# Generate a random 6-digit OTP
def generate_otp():
    return str(random.randint(100000, 999999))

@app.route("/sms_otp", methods=["GET", "POST"])
@login_required
def sms_otp():
    if request.method == "POST":
        phone_number = request.form["phone_number"]
        # Save the phone number to the user’s profile
        current_user.phone_number = phone_number
        db.session.commit()

        # Generate and send OTP via Twilio
        otp = generate_otp()
        session["otp"] = otp  # Save OTP in session temporarily

        message = client.messages.create(
            body=f"Your OTP is: {otp}",
            from_=TWILIO_PHONE_NUMBER,
            to=phone_number
        )

        flash("OTP sent to your phone!", "success")
        return redirect(url_for("verify_otp"))

    return render_template("sms_otp.html")

@app.route("/verify_sms", methods=["GET", "POST"])
@login_required
def verify_otp():
    if request.method == "POST":
        entered_otp = request.form["otp"]
        if entered_otp == session.get("otp"):
            flash("OTP Verified Successfully!", "success")
            current_user.sms_mfa_completed = True
            db.session.commit()
            return redirect(url_for("home"))
        else:
            flash("Invalid OTP. Please try again.", "danger")

    return render_template("verify_sms.html")

def generate_email_otp():
    return str(random.randint(100000, 999999))

@app.route('/email_otp', methods=['GET', 'POST'])
@login_required
def email_otp():
    if request.method == 'POST':
        email = request.form.get('email')
        
        # Save the email to user's record
        current_user.email = email
        db.session.commit()

        # Generate OTP and store in session
        otp = generate_email_otp()
        session['email_otp'] = otp

        # Send email with OTP
        msg = Message("Your Email OTP", sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f"Your OTP is: {otp}"
        mail.send(msg)

        flash("OTP sent to your email!", "success")
        return redirect(url_for('verify_email_otp'))

    return render_template('email_otp.html')

@app.route('/verify_email_otp', methods=['GET', 'POST'])
@login_required
def verify_email_otp():
    if request.method == 'POST':
        user_otp = request.form.get('otp')

        if user_otp == session.get('email_otp'):
            current_user.email_mfa_completed = True
            db.session.commit()
            session.pop('email_otp', None)
            
            flash("Email OTP verified successfully!", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid OTP, please try again.", "danger")

    return render_template('verify_email_otp.html')

@app.route('/totp_setup')
@login_required
def totp_setup():
    if not current_user.totp_secret:
        # Generate new TOTP secret
        current_user.totp_secret = pyotp.random_base32()
        db.session.commit()

    totp_uri = pyotp.totp.TOTP(current_user.totp_secret).provisioning_uri(
        name=current_user.email or current_user.username,
        issuer_name="YourApp"
    )

    # Generate QR code
    qr_img = qrcode.make(totp_uri)
    buf = io.BytesIO()
    qr_img.save(buf)
    qr_data = base64.b64encode(buf.getvalue()).decode('utf-8')

    return render_template('totp_setup.html', qr_data=qr_data)

@app.route('/verify_totp', methods=['GET', 'POST'])
@login_required
def verify_totp():
    if request.method == 'POST':
        user_totp = request.form.get('totp')
        totp = pyotp.TOTP(current_user.totp_secret)

        if totp.verify(user_totp):
            current_user.totp_mfa_completed = True
            db.session.commit()
            flash("Authenticator app (TOTP) setup successful!", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid TOTP. Please try again.", "danger")

    return render_template('verify_totp.html')

@app.route('/magic_link', methods=['GET', 'POST'])
@login_required
def magic_link():
    if request.method == 'POST':
        token = secrets.token_urlsafe(32)
        current_user.magic_link_token = token
        current_user.magic_link_expiry = datetime.utcnow() + timedelta(minutes=15)  # link valid for 15 mins
        db.session.commit()

        magic_link_url = url_for('verify_magic_link', token=token, _external=True)

        # Send email with the magic link
        msg = Message("Your Magic Link", sender=app.config['MAIL_USERNAME'], recipients=[current_user.email])
        msg.body = f"Click the following link to log in: {magic_link_url}"
        mail.send(msg)

        flash("Magic link sent to your email!", "success")
        return redirect(url_for('home'))

    return render_template('magic_link.html')

# Route to verify Magic Link
@app.route('/verify_magic_link/<token>')
def verify_magic_link(token):
    user = User.query.filter_by(magic_link_token=token).first()

    if user and user.magic_link_expiry > datetime.utcnow():
        user.magic_link_completed = True
        user.magic_link_token = None  # Clear token after use
        user.magic_link_expiry = None
        db.session.commit()

        flash("Magic link authentication successful!", "success")
        login_user(user)
        return redirect(url_for('home'))
    else:
        flash("Magic link is invalid or expired.", "danger")
        return redirect(url_for('login'))


    
if __name__ == "__main__":        
    with app.app_context():
        db.create_all()
    app.run(debug=True)
