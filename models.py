from flask_sqlalchemy import SQLAlchemy 
from flask_login import UserMixin
from datetime import datetime
from sqlalchemy.dialects.postgresql import ARRAY  # For PostgreSQL


db = SQLAlchemy()

def connect_db(app):
    """Connect this database to the provided Flask app."""
    db.app = app
    db.init_app(app)

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    reset_token = db.Column(db.String(128), nullable=True)
    token_expiration = db.Column(db.DateTime, nullable=True)
    # Relationship to reviews
    reviews = db.relationship('Review', back_populates='user', cascade="all, delete-orphan")
    old_passwords = db.Column(ARRAY(db.String), default=[])

class Review(db.Model):
    __tablename__ = "reviews"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    user = db.relationship('User', back_populates='reviews')


