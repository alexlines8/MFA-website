from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    phone_number = db.Column(db.String(20), unique=True, nullable=True)
    sms_mfa_completed = db.Column(db.Boolean, default=False)
    email = db.Column(db.String(150), unique=True, nullable=True)
    email_mfa_completed = db.Column(db.Boolean, default=False)
    totp_secret = db.Column(db.String(16), nullable=True)
    totp_mfa_completed = db.Column(db.Boolean, default=False)
    magic_link_token = db.Column(db.String(100), nullable=True)
    magic_link_expiry = db.Column(db.DateTime, nullable=True)
    magic_link_completed = db.Column(db.Boolean, default=False)

