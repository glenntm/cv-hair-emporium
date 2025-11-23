from flask import Flask, render_template, request, redirect, url_for, flash, session, get_flashed_messages, jsonify  
from flask_sqlalchemy import SQLAlchemy 
from flask_migrate import Migrate
from flask_login import login_user, LoginManager, login_required, logout_user, current_user
# Environment variables are now loaded using os.getenv()
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, Form, validators
from wtforms.validators import InputRequired,Length, ValidationError,DataRequired, Email, length, Regexp
from models import User, db, connect_db, Review
from flask_bcrypt import Bcrypt, check_password_hash, generate_password_hash
import psycopg2
from psycopg2 import sql
from flask_json import FlaskJSON, JsonError, json_response
from authlib.integrations.flask_client import OAuth
from authlib.jose import jwt, JoseError
from authlib.jose.errors import ExpiredTokenError
import json
import os
import uuid
import requests
from flask_mail import Mail, Message
from datetime import datetime, timedelta, timezone
import secrets 
from math import ceil
from flask_bootstrap import Bootstrap5
from werkzeug.security import check_password_hash
import dropbox





app = Flask(__name__)
bootstrap = Bootstrap5(app)
json = FlaskJSON(app)
bcrypt = Bcrypt(app)
mail = Mail(app) # instantiate the mail class 

#for CSRF token
app.config['SECRET_KEY'] = os.getenv("CRSF_SECRET")
if not app.config['SECRET_KEY']:
    # Fallback to secret.py for local development
    try:
        from secret import crsf_secret
        app.config['SECRET_KEY'] = crsf_secret
    except ImportError:
        # If secret.py doesn't exist, generate a random key (not secure for production!)
        app.config['SECRET_KEY'] = secrets.token_hex(32)
        print("⚠️  WARNING: Using generated SECRET_KEY. Set CRSF_SECRET environment variable or add crsf_secret to secret.py")


# configuration of mail 
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'danotoriousg@gmail.com'
app.config['MAIL_PASSWORD'] = os.getenv("GMAIL_PASSWORD")
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app) 


#database setup
# Railway provides DATABASE_URL as a complete connection string
database_url = os.getenv("DATABASE_URL")

# Debug: Check if we're in Railway production (based on Railway env vars)
railway_env = os.getenv("RAILWAY_ENVIRONMENT_ID") or os.getenv("RAILWAY_SERVICE_NAME")

if database_url:
    # Use Railway DATABASE_URL
    print(f"Found DATABASE_URL, connecting to Railway PostgreSQL...")
elif railway_env:
    # We're on Railway but DATABASE_URL not set - try individual vars
    print("Railway detected but DATABASE_URL not found, trying individual vars...")
    db_user = os.getenv("PGUSER")
    db_password = os.getenv("PGPASSWORD")
    db_host = os.getenv("PGHOST")
    db_port = os.getenv("PGPORT") or "5432"
    db_name = os.getenv("PGDATABASE")
    
    if all([db_user, db_password, db_host, db_name]):
        database_url = f'postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}'
        print(f"Using Railway PostgreSQL with individual vars...")
    else:
        print("ERROR: Railway environment detected but database credentials missing!")
else:
    # Get database connection details with fallbacks (for local dev)
    db_user = os.getenv("PGUSER") or os.getenv("DATABASE_USERNAME")
    db_password = os.getenv("PGPASSWORD") or os.getenv("DATABASE_PASSWORD") 
    db_host = os.getenv("PGHOST") or os.getenv("DATABASE_HOST") or "localhost"
    db_port = os.getenv("PGPORT") or os.getenv("DATABASE_PORT") or "5432"
    db_name = os.getenv("PGDATABASE") or os.getenv("POSTGRES_DB") or os.getenv("DATABASE_NAME")

# Debug: Print all environment variables
print("=== ALL ENVIRONMENT VARIABLES ===")
dropbox_vars_found = []
for key, value in os.environ.items():
    if 'PG' in key or 'DATABASE' in key or 'RAILWAY' in key or 'DROPBOX' in key:
        if 'DROPBOX' in key:
            dropbox_vars_found.append(key)
            # Show DROPBOX token info but mask the actual token
            if value:
                if 'REFRESH' in key:
                    print(f"{key}=[LENGTH: {len(value)} chars] {value[:30]}...{value[-10:]}")
                else:
                    print(f"{key}=[LENGTH: {len(value)} chars] {value[:20]}...{value[-10:] if len(value) > 30 else ''}")
            else:
                print(f"{key}=None or empty")
        else:
            print(f"{key}={value[:50] if value else 'None'}...")  # Show first 50 chars for debugging

# Explicitly check for required DROPBOX variables
print("\n=== DROPBOX VARIABLES CHECK ===")
required_vars = ['DROPBOX_ACCESS_TOKEN', 'DROPBOX_REFRESH_TOKEN', 'DROPBOX_APP_KEY', 'DROPBOX_APP_SECRET']
for var in required_vars:
    value = os.getenv(var)
    if value:
        print(f"✅ {var}: Found ({len(value)} chars)")
    else:
        print(f"❌ {var}: MISSING")
print("=== END DROPBOX VARIABLES CHECK ===")
print("=== END ENVIRONMENT VARIABLES ===")

# Auto-detect environment: local development vs production
if database_url:
    # Use Railway DATABASE_URL
    print("Using Railway PostgreSQL database for production...")
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    # Fallback to local PostgreSQL for development
    print("Using local PostgreSQL database for development...")
    # Local PostgreSQL configuration (only for local development)
    db_user = "glenntm"  # Your local PostgreSQL username
    db_password = "howdydeeodoo43"  # Replace with your actual local password
    db_host = "localhost"  # Local PostgreSQL host
    db_port = "5432"  # Local PostgreSQL port
    db_name = "cv_hair_emporium"  # Your local database name
    print(f"Connecting to: postgresql://{db_user}:***@{db_host}:{db_port}/{db_name}")
    app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

connect_db(app)

# Create database tables after db is initialized
with app.app_context():
    db.create_all()
    print("Database tables created successfully!")


# These variables are already defined above with fallbacks
bcrypt = Bcrypt(app)

migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view='login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#for google sso setup
appConf = {
    "OAUTH2_CLIENT_ID": f"{os.getenv('GOOGLE_CLIENT_ID')}",
    "OAUTH2_CLIENT_SECRET": f"{os.getenv('GOOGLE_CLIENT_SECRET')}",
    "OAUTH_META_URL": "https://accounts.google.com/.well-known/openid-configuration",
    "FLASK_SECRET": f"{os.getenv('FLASK_SECRET')}",
    "FLASK_PORT":5000
}

oauth = OAuth(app)
oauth.register("myApp",
               client_id = appConf.get("OAUTH2_CLIENT_ID"),
               client_secret = appConf.get("OAUTH2_CLIENT_SECRET"),
               server_metadata_url= appConf.get("OAUTH_META_URL"),
               client_kwargs = {
                   "scope": "openid profile email" #https://www.googleapis.com/auth/user.gender.read https://www.googleapis.com/auth/user.birthday.read
               }
               )

class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=2, max=80)], render_kw={"placeholder": "First Name"} )
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=80)], render_kw={"placeholder": "Last Name"} )
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)], render_kw={"placeholder": "Email"} )
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=128)], render_kw={"placeholder": "Password"} )
    submit = SubmitField('Register')

    def email_exists(self, email):
    # Query the database to check if the email already exists
        existing_email = User.query.filter_by(email=email.data).first()
        if existing_email:
            # If a user is found, raise a validation error
            raise ValidationError('This email is already registered.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)], render_kw={"placeholder": "Email"} )
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=128)], render_kw={"placeholder": "Password"} )
    submit = SubmitField('Login')

#api info for cal.com bookings
cal_url = "https://api.cal.com/v2/bookings"

headers = {
    "cal-api-version": "2024-08-13",
    "Authorization": f"{os.getenv('CAL_BEARER_TOKEN')}"
}

response = requests.request("GET", cal_url, headers=headers)

#parse the json
cal_json = response.json()

#Classes for password requirements
class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', 
                             validators=[
                                 DataRequired(),
                                 Length(min=8),
                                 Regexp(r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])', message="Password must contain at least one uppercase letter, one number, and one special character.")
                             ])
    submit = SubmitField('Reset Password')

class RegistrationFormPassword(FlaskForm):
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.Length(min=8, message="Password must be at least 8 characters long."),
        validators.Regexp(r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])',
                          message="Password must include at least one uppercase letter, one number, and one special character.")
    ])
    submit = SubmitField('Register')


@app.route("/forgot-password", methods=['GET', 'POST']) 
def forgot_password(): 
   form = LoginForm()
   if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            # Generate a secure token
            token = secrets.token_hex(32)
            user.reset_token = token
            user.token_expiration = datetime.now() + timedelta(hours=1)
            db.session.commit()

            # Send the reset email
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('[CV Hair Emporium]: Password Reset Request',
            sender ='danotoriousg@gmail.com', 
                          recipients=[email],
                          body=f'''
                        We received a request to reset your password for your account. Click the link below to set a new password:
                        {reset_url}
                        
                        If you didn’t request a password reset, you can ignore this email—your password will remain unchanged.
                        
                        Best,
                        CV Hair Emporium Team
                            ''')
            mail.send(msg)
            flash('Password reset email sent. Check your inbox.', 'info')
            return render_template('home.html')
        else:
            flash('Email not found.', 'warning')
            return render_template('forgotPw.html', form=form)

   return render_template('forgotPw.html', form=form)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    form = LoginForm()
    user = User.query.filter_by(reset_token=token).first()

    if not user or user.token_expiration < datetime.now():
        return render_template('pwTokenExpiration.html')

    if request.method == 'POST':
        new_password = request.form['password']

        # Check if the new password matches the current password
        if bcrypt.check_password_hash(user.password, new_password):
            return "You cannot reuse your current password. Please choose a different password."

        # Optionally, check against old passwords (if you store them)
        if user.old_passwords:
            for old_pw in user.old_passwords:
                if bcrypt.check_password_hash(old_pw, new_password):
                    return "You cannot reuse a previous password. Please choose a different password."

        # Hash the new password
        new_password_hashed = bcrypt.generate_password_hash(new_password).decode('utf-8')

        # Update the user's password and store the old password
        if user.old_passwords is None:
            user.old_passwords = []  # Initialize old_passwords if it's None

        user.old_passwords.append(user.password)  # Save the current password as the previous password

        # Update user's password, reset token, and expiration
        user.password = new_password_hashed
        user.reset_token = None
        user.token_expiration = None

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()  # Rollback in case of an error
            print(f"Error updating password: {e}")
            return "An error occurred while updating your password."

        return render_template('resetPwConfirmation.html')

    return render_template('resetPw.html', form=form, token=token)
@app.route('/token-password-expiration')
def tokenPasswordExpiration():
    return render_template('pwTokenExpiration.html')

@app.route('/reset-password-confirmation')
def resetPasswordConfirmation():
    return render_template('resetPwConfirmation.html')

@app.route('/')
def home():
    recent_reviews = Review.query.order_by(Review.updated_at.desc()).limit(3).all()


    return render_template('home.html', cal_url = response.text, recent_reviews=recent_reviews)

@app.route('/gallery')
def gallery():
    return render_template('gallery.html')

# Dropbox OAuth endpoints for getting refresh token
@app.route('/dropbox-auth')
def dropbox_auth():
    """Initiate Dropbox OAuth flow to get refresh token"""
    app_key = os.getenv('DROPBOX_APP_KEY')
    
    if not app_key:
        # Try to get from secret.py for local dev
        try:
            from secret import dropbox_app_key
            app_key = dropbox_app_key
        except ImportError:
            return '''
            <h1>Dropbox OAuth Setup</h1>
            <p>❌ DROPBOX_APP_KEY not found. Please set it in Railway or secret.py</p>
            <p>Get your App Key from: <a href="https://www.dropbox.com/developers/apps">https://www.dropbox.com/developers/apps</a></p>
            <p>Go to your app → Settings → App key & secret</p>
            ''', 400
    
    # Generate state for security
    state = secrets.token_urlsafe(32)
    session['dropbox_oauth_state'] = state
    
    # Build OAuth URL with offline access to get refresh token
    redirect_uri = url_for('dropbox_callback', _external=True)
    oauth_url = (
        f"https://www.dropbox.com/oauth2/authorize?"
        f"client_id={app_key}&"
        f"response_type=code&"
        f"redirect_uri={redirect_uri}&"
        f"token_access_type=offline&"  # This requests a refresh token
        f"state={state}"
    )
    
    return redirect(oauth_url)

@app.route('/dropbox-callback')
def dropbox_callback():
    """Handle Dropbox OAuth callback and exchange code for tokens"""
    # Verify state
    stored_state = session.get('dropbox_oauth_state')
    received_state = request.args.get('state')
    
    if not stored_state or stored_state != received_state:
        return '''
        <h1>❌ OAuth Error</h1>
        <p>Invalid state parameter. Please try again.</p>
        <a href="/dropbox-auth">Try Again</a>
        ''', 400
    
    # Check for errors
    error = request.args.get('error')
    if error:
        error_description = request.args.get('error_description', 'Unknown error')
        return f'''
        <h1>❌ OAuth Error</h1>
        <p>Error: {error}</p>
        <p>Description: {error_description}</p>
        <a href="/dropbox-auth">Try Again</a>
        ''', 400
    
    # Get authorization code
    code = request.args.get('code')
    if not code:
        return '''
        <h1>❌ OAuth Error</h1>
        <p>No authorization code received.</p>
        <a href="/dropbox-auth">Try Again</a>
        ''', 400
    
    # Get app credentials
    app_key = os.getenv('DROPBOX_APP_KEY')
    app_secret = os.getenv('DROPBOX_APP_SECRET')
    
    if not app_key or not app_secret:
        # Try to get from secret.py for local dev
        try:
            from secret import dropbox_app_key, dropbox_app_secret
            app_key = dropbox_app_key
            app_secret = dropbox_app_secret
        except ImportError:
            return '''
            <h1>❌ Configuration Error</h1>
            <p>DROPBOX_APP_KEY and DROPBOX_APP_SECRET not found.</p>
            <p>Please set them in Railway or secret.py</p>
            ''', 500
    
    # Exchange code for tokens
    redirect_uri = url_for('dropbox_callback', _external=True)
    
    try:
        token_response = requests.post(
            'https://api.dropbox.com/oauth2/token',
            data={
                'code': code,
                'grant_type': 'authorization_code',
                'client_id': app_key,
                'client_secret': app_secret,
                'redirect_uri': redirect_uri
            }
        )
        
        if token_response.status_code != 200:
            return f'''
            <h1>❌ Token Exchange Failed</h1>
            <p>Status: {token_response.status_code}</p>
            <p>Response: {token_response.text}</p>
            <a href="/dropbox-auth">Try Again</a>
            ''', 500
        
        token_data = token_response.json()
        access_token = token_data.get('access_token')
        refresh_token = token_data.get('refresh_token')
        expires_in = token_data.get('expires_in', 'Unknown')
        
        if not refresh_token:
            return '''
            <h1>⚠️ Warning</h1>
            <p>No refresh token received. Make sure you included <code>token_access_type=offline</code> in the OAuth URL.</p>
            <p>Access Token: {access_token[:50]}...</p>
            <a href="/dropbox-auth">Try Again</a>
            ''', 400
        
        # Display tokens for user to copy
        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dropbox OAuth Success</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    max-width: 800px;
                    margin: 50px auto;
                    padding: 20px;
                    background: #f5f5f5;
                }}
                .container {{
                    background: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                h1 {{
                    color: #0061ff;
                }}
                .success {{
                    color: #00a86b;
                    font-weight: bold;
                }}
                .token-box {{
                    background: #f8f9fa;
                    border: 1px solid #dee2e6;
                    border-radius: 4px;
                    padding: 15px;
                    margin: 15px 0;
                    word-break: break-all;
                    font-family: monospace;
                    font-size: 12px;
                }}
                .instructions {{
                    background: #fff3cd;
                    border: 1px solid #ffc107;
                    border-radius: 4px;
                    padding: 15px;
                    margin: 20px 0;
                }}
                .warning {{
                    background: #f8d7da;
                    border: 1px solid #dc3545;
                    border-radius: 4px;
                    padding: 15px;
                    margin: 20px 0;
                }}
                button {{
                    background: #0061ff;
                    color: white;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 4px;
                    cursor: pointer;
                    margin: 5px;
                }}
                button:hover {{
                    background: #0052d9;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>✅ Dropbox OAuth Successful!</h1>
                <p class="success">You have successfully authorized the app and received tokens.</p>
                
                <div class="instructions">
                    <h3>📋 Next Steps:</h3>
                    <ol>
                        <li>Copy the tokens below</li>
                        <li>Add them to Railway environment variables:</li>
                        <ul>
                            <li><code>DROPBOX_ACCESS_TOKEN</code> = Access Token (below)</li>
                            <li><code>DROPBOX_REFRESH_TOKEN</code> = Refresh Token (below)</li>
                            <li><code>DROPBOX_APP_KEY</code> = Your App Key</li>
                            <li><code>DROPBOX_APP_SECRET</code> = Your App Secret</li>
                        </ul>
                        <li>Also update <code>secret.py</code> with the new access token for local development</li>
                        <li>Redeploy your Railway app</li>
                    </ol>
                </div>
                
                <h3>Access Token (expires in {expires_in} seconds):</h3>
                <div class="token-box" id="access-token">{access_token}</div>
                <button onclick="copyToClipboard('access-token')">Copy Access Token</button>
                
                <h3>Refresh Token (long-lived, keep secure!):</h3>
                <div class="token-box" id="refresh-token">{refresh_token}</div>
                <button onclick="copyToClipboard('refresh-token')">Copy Refresh Token</button>
                
                <div class="warning">
                    <strong>⚠️ Important:</strong>
                    <ul>
                        <li>Keep the refresh token secure - it allows generating new access tokens</li>
                        <li>Don't commit these tokens to git</li>
                        <li>The access token will expire, but the refresh token can generate new ones automatically</li>
                    </ul>
                </div>
                
                <p><a href="/gallery">Go to Gallery</a> | <a href="/dropbox-auth">Re-authorize</a></p>
            </div>
            
            <script>
                function copyToClipboard(elementId) {{
                    const element = document.getElementById(elementId);
                    const text = element.textContent;
                    navigator.clipboard.writeText(text).then(function() {{
                        alert('Copied to clipboard!');
                    }}, function(err) {{
                        // Fallback for older browsers
                        const textArea = document.createElement('textarea');
                        textArea.value = text;
                        document.body.appendChild(textArea);
                        textArea.select();
                        document.execCommand('copy');
                        document.body.removeChild(textArea);
                        alert('Copied to clipboard!');
                    }});
                }}
            </script>
        </body>
        </html>
        '''
        
    except Exception as e:
        return f'''
        <h1>❌ Error</h1>
        <p>Failed to exchange code for tokens: {str(e)}</p>
        <a href="/dropbox-auth">Try Again</a>
        ''', 500

# Cache for temporary links with expiration tracking
# Format: {path: {'url': link, 'expires_at': datetime}}
_temp_link_cache = {}

@app.route('/api/gallery-images')
@app.route('/api/gallery-images/<int:page>')
@app.route('/api/gallery-images/<int:page>/<int:per_page>')
def get_gallery_images(page=1, per_page=20):
    """Fetch images from Dropbox folder and return as JSON"""
    try:
        # Initialize Dropbox client with access token
        # Try environment variable first (for production), then fall back to secret.py (for local dev)
        access_token = os.getenv('DROPBOX_ACCESS_TOKEN')
        token_source = "environment variable"
        
        if not access_token:
            try:
                from secret import dropbox_access_token
                access_token = dropbox_access_token
                token_source = "secret.py file"
            except ImportError:
                error_msg = 'Dropbox access token not configured. Set DROPBOX_ACCESS_TOKEN environment variable or add to secret.py'
                print(f"❌ {error_msg}")
                return jsonify({'error': error_msg}), 500
        
        if not access_token or access_token == 'your_dropbox_access_token_here' or len(access_token.strip()) == 0:
            error_msg = 'Please configure your Dropbox access token. Token is missing or empty.'
            print(f"❌ {error_msg}")
            return jsonify({'error': error_msg}), 500
        
        # Validate token format (Dropbox tokens typically start with specific patterns)
        if len(access_token) < 20:
            error_msg = 'Dropbox access token appears to be invalid (too short).'
            print(f"❌ {error_msg}")
            return jsonify({'error': error_msg}), 500
        
        # Initialize Dropbox client with verbose output
        print(f"📡 Connecting to Dropbox...")
        print(f"   Token source: {token_source}")
        print(f"   Token length: {len(access_token)} characters")
        print(f"   Token preview: {access_token[:20]}...{access_token[-10:] if len(access_token) > 30 else ''}")
        # Additional debug: check if token matches expected length
        if len(access_token) != 1309:
            print(f"   ⚠️  WARNING: Token length is {len(access_token)}, expected 1309 characters!")
        
        # Check if we have refresh token credentials for automatic refresh
        refresh_token = os.getenv('DROPBOX_REFRESH_TOKEN')
        app_key = os.getenv('DROPBOX_APP_KEY')
        app_secret = os.getenv('DROPBOX_APP_SECRET')
        
        # Fallback to secret.py for local dev
        if not refresh_token:
            try:
                from secret import dropbox_refresh_token
                refresh_token = dropbox_refresh_token
            except (ImportError, AttributeError):
                pass
        
        if not app_key:
            try:
                from secret import dropbox_app_key
                app_key = dropbox_app_key
            except (ImportError, AttributeError):
                pass
        
        if not app_secret:
            try:
                from secret import dropbox_app_secret
                app_secret = dropbox_app_secret
            except (ImportError, AttributeError):
                pass
        
        # Debug: Log what credentials we have
        print(f"   Refresh token available: {'Yes' if refresh_token else 'No'}")
        print(f"   App key available: {'Yes' if app_key else 'No'}")
        print(f"   App secret available: {'Yes' if app_secret else 'No'}")
        
        try:
            # If we have refresh token credentials, pass them to enable auto-refresh
            if refresh_token and app_key and app_secret:
                print(f"   Using Dropbox client with refresh token support...")
                dbx = dropbox.Dropbox(
                    oauth2_access_token=access_token,
                    oauth2_refresh_token=refresh_token,
                    app_key=app_key,
                    app_secret=app_secret
                )
            else:
                # Fallback to access token only (no auto-refresh)
                print(f"   Using Dropbox client with access token only (no refresh support)...")
                dbx = dropbox.Dropbox(access_token)
            
            # Verify token is valid
            print(f"   Verifying token...")
            account = dbx.users_get_current_account()
            print(f"✅ Connected to Dropbox as: {account.name.display_name}")
            print(f"   Account email: {account.email}")
        except dropbox.exceptions.AuthError as auth_err:
            error_detail = str(auth_err)
            print(f"❌ Authentication failed: {error_detail}")
            
            # Try to refresh token if we have refresh token credentials
            if refresh_token and app_key and app_secret and 'expired_access_token' in error_detail:
                print(f"   🔄 Attempting to refresh access token...")
                try:
                    # Refresh the access token
                    refresh_response = requests.post(
                        'https://api.dropbox.com/oauth2/token',
                        data={
                            'grant_type': 'refresh_token',
                            'refresh_token': refresh_token,
                            'client_id': app_key,
                            'client_secret': app_secret
                        }
                    )
                    
                    if refresh_response.status_code == 200:
                        new_token_data = refresh_response.json()
                        new_access_token = new_token_data.get('access_token')
                        # Refresh token might be updated, use new one if provided, otherwise keep the old one
                        new_refresh_token = new_token_data.get('refresh_token') or refresh_token
                        print(f"   ✅ Successfully refreshed access token!")
                        
                        # Update the token and retry with refresh token support
                        access_token = new_access_token
                        dbx = dropbox.Dropbox(
                            oauth2_access_token=new_access_token,
                            oauth2_refresh_token=new_refresh_token,
                            app_key=app_key,
                            app_secret=app_secret
                        )
                        account = dbx.users_get_current_account()
                        print(f"✅ Connected to Dropbox as: {account.name.display_name}")
                        print(f"   ⚠️  NOTE: New token generated. Consider updating DROPBOX_ACCESS_TOKEN in Railway with new token (optional - refresh will work automatically).")
                        print(f"   New token preview: {new_access_token[:20]}...{new_access_token[-10:]}")
                    else:
                        print(f"   ❌ Failed to refresh token: {refresh_response.text}")
                        return jsonify({'error': 'Dropbox token expired and refresh failed. Please generate a new access token.'}), 500
                except Exception as refresh_err:
                    print(f"   ❌ Error refreshing token: {refresh_err}")
                    return jsonify({'error': 'Dropbox token expired. Please generate a new access token from https://www.dropbox.com/developers/apps'}), 500
            else:
                # No refresh token available, return error with helpful message
                if 'expired_access_token' in error_detail:
                    missing_vars = []
                    if not refresh_token:
                        missing_vars.append('DROPBOX_REFRESH_TOKEN')
                    if not app_key:
                        missing_vars.append('DROPBOX_APP_KEY')
                    if not app_secret:
                        missing_vars.append('DROPBOX_APP_SECRET')
                    
                    if missing_vars:
                        error_msg = f'''Dropbox access token has expired and cannot be refreshed because the following Railway environment variables are missing: {', '.join(missing_vars)}. 

Please add these variables to your Railway project:
1. Go to your Railway project → Variables tab
2. Add DROPBOX_REFRESH_TOKEN, DROPBOX_APP_KEY, and DROPBOX_APP_SECRET
3. Redeploy your application

You can get these values from your secret.py file or regenerate them using the /dropbox-auth endpoint.'''
                    else:
                        error_msg = 'Dropbox access token has expired. Please check your refresh token credentials.'
                else:
                    error_msg = f'Dropbox authentication failed: {error_detail}'
                return jsonify({'error': error_msg}), 500
        
        # List files in your Dropbox folder
        # Your folder: Mobile Uploads
        folder_path = '/Mobile Uploads'
        
        print(f"📁 Attempting to list folder: {folder_path}")
        try:
            result = dbx.files_list_folder(folder_path)
            print(f"✅ Successfully listed {len(result.entries)} items in folder")
        except dropbox.exceptions.ApiError as e:
            error_detail = str(e)
            print(f"❌ Error listing folder: {error_detail}")
            # Check if it's a permission or path error
            if 'not_found' in error_detail.lower() or 'path' in error_detail.lower():
                error_msg = f"Folder '{folder_path}' not found in Dropbox. Please verify the folder exists and the path is correct."
            elif 'insufficient_scope' in error_detail.lower() or 'permission' in error_detail.lower():
                error_msg = "Insufficient permissions. The Dropbox app needs 'files.metadata.read' and 'files.content.read' permissions. Regenerate your access token after enabling these permissions."
            else:
                error_msg = f"Error accessing Dropbox folder: {error_detail}"
            return jsonify({'error': error_msg}), 500
        
        # First, collect all image entries to determine total count
        image_entries = []
        for entry in result.entries:
            if isinstance(entry, dropbox.files.FileMetadata):
                if entry.name.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp')):
                    image_entries.append(entry)
        
        # Sort images by modification date (newest first)
        # Images without a modification date will be sorted to the end
        # Use a very old date (1970-01-01) for entries without server_modified
        min_date = datetime(1970, 1, 1, tzinfo=timezone.utc)
        image_entries.sort(
            key=lambda x: x.server_modified if x.server_modified else min_date,
            reverse=True
        )
        
        print(f"📊 Sorted {len(image_entries)} images by modification date (newest first)")
        
        # Calculate pagination boundaries
        total_images = len(image_entries)
        start_idx = (page - 1) * per_page
        end_idx = min(start_idx + per_page, total_images)
        
        print(f"📊 Found {total_images} images. Showing page {page} (images {start_idx+1} to {end_idx})")
        
        # Only process images for current page
        all_images = []
        current_time = datetime.now(timezone.utc)
        
        for entry in image_entries[start_idx:end_idx]:
            # Get temporary direct link (this works reliably)
            cache_key = entry.path_display
            image_url = None
            
            # Check if we have a cached link that's still valid
            if cache_key in _temp_link_cache:
                cached_data = _temp_link_cache[cache_key]
                # Check if link is still valid (refresh if less than 30 minutes until expiration)
                if cached_data['expires_at'] > current_time + timedelta(minutes=30):
                    image_url = cached_data['url']
                    print(f"   ✓ Using cached link for {entry.name} (expires in {(cached_data['expires_at'] - current_time).total_seconds() / 3600:.1f}h)")
                else:
                    # Link is about to expire or expired, remove from cache
                    print(f"   ⚠️  Cached link for {entry.name} expired or expiring soon, refreshing...")
                    del _temp_link_cache[cache_key]
            
            # If no valid cached link, get a new one
            if not image_url:
                try:
                    # Get temporary direct link
                    temp_link_result = dbx.files_get_temporary_link(entry.path_display)
                    image_url = temp_link_result.link
                    # Cache it with expiration time (Dropbox links expire after 4 hours)
                    expires_at = current_time + timedelta(hours=3, minutes=50)  # Refresh 10 min before 4h expiration
                    _temp_link_cache[cache_key] = {
                        'url': image_url,
                        'expires_at': expires_at
                    }
                    print(f"   ✓ Generated new link for {entry.name} (valid until {expires_at.strftime('%H:%M:%S')} UTC)")
                except Exception as e:
                    print(f"⚠️  Failed to get temporary link for {entry.name}: {e}")
                    continue
            
            all_images.append({
                'name': entry.name,
                'url': image_url,
                'size': entry.size,
                'modified': entry.server_modified.isoformat() if entry.server_modified else None
            })
        
        # Calculate pagination info
        total_pages = (total_images + per_page - 1) // per_page
        
        print(f"✅ Returning {len(all_images)} images for page {page} of {total_pages}")
        
        response = jsonify({
            'images': all_images,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total_images,
                'total_pages': total_pages,
                'has_next': page < total_pages,
                'has_prev': page > 1
            }
        })
        
        # Add caching headers for better performance
        response.cache_control.max_age = 300  # Cache API response for 5 minutes
        
        return response
        
    except dropbox.exceptions.BadInputError as e:
        error_detail = str(e)
        if 'files.metadata.read' in error_detail:
            error_msg = "Dropbox app needs 'files.metadata.read' permission. Go to https://www.dropbox.com/developers/apps, select your app, Permissions tab, and enable 'files.metadata.read' scope, then regenerate your access token."
        else:
            error_msg = f"Dropbox API returned invalid data: {error_detail}"
        print(f"❌ Dropbox BadInput Error: {error_detail}")
        return jsonify({'error': error_msg}), 500
    except dropbox.exceptions.ApiError as e:
        error_detail = str(e)
        error_msg = f"Dropbox API error: {error_detail}"
        print(f"❌ Dropbox API Error: {error_detail}")
        return jsonify({'error': error_msg}), 500
    except Exception as e:
        error_msg = str(e)
        print(f"❌ Unexpected error fetching Dropbox images: {error_msg}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to fetch images: {error_msg}'}), 500

@app.route('/reviews', methods=['GET', 'POST'])
def reviews_page():

    # Handle new review submission (if applicable)
    if request.method == 'POST':
        review = Review(
            name=request.form['name'],
            review=request.form['review'],
            user_id=current_user.id,  # Assuming user association
        )
        db.session.add(review)
        db.session.commit()

    # Get filter from query parameters
    filter_type = request.args.get('filter', 'all')

    # Base query
    if filter_type == 'mine':
        reviews_query = Review.query.filter_by(user_id=current_user.id)
    else:
        reviews_query = Review.query  # All reviews

    # Pagination setup
    page = request.args.get('page', 1, type=int)
    per_page = 5  # Number of items per page
    pagination = reviews_query.order_by(Review.created_at.desc()).paginate(page=page, per_page=per_page)

    # Reviews for the current page
    reviews = pagination.items

    # Process the datetime
    for review in reviews:
        review.date_formatted = review.updated_at.strftime("%B %d, %Y")  # Example: "January 23, 2025"

    return render_template('reviews.html', reviews=reviews, pagination=pagination, filter_type=filter_type)

@app.route('/write-review', methods=['GET', 'POST'])
@login_required
def write_reviews():

    if request.method == 'POST':
        # Debugging
        print(f"Form Data: {request.form}")
        try:
            rating = request.form.get('rating')
            comment = request.form.get('Message')

            if not rating or int(rating) not in range(1, 6):
                flash("Invalid rating. Please select a rating between 1 and 5.", "error")
                return redirect(request.referrer)

            new_review = Review(user_id=current_user.id, rating=int(rating), comment=comment)
            db.session.add(new_review)
            db.session.commit()

            flash("Thank you for your review!", "success")
            return redirect(url_for('reviews_page'))
        except Exception as e:
            db.session.rollback()
            print(f"Error: {e}")
            flash("An error occurred while submitting your review. Please try again.", "error")
            return redirect(request.referrer)
        
    return render_template('writeReview.html', user=current_user )

@app.route('/edit_review/<int:review_id>', methods=['GET', 'POST'])
@login_required  # Ensure the user is logged in
def edit_review(review_id):
    # Fetch the review
    review = Review.query.get_or_404(review_id)

    # Ensure the current user owns the review
    if review.user_id != current_user.id:
        flash('You are not authorized to edit this review.', 'danger')
        return redirect(url_for('reviews_page'))

    if request.method == 'POST':
        # Update the review content
        review.comment = request.form['comment']
        review.updated_at = datetime.utcnow()  # Update the timestamp
        review.rating = request.form['rating']
        db.session.commit()
        flash('Your review has been updated!', 'success')
        return redirect(url_for('reviews_page'))

    return render_template('editReview.html', review=review)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    #prevents logged in user from access the login page
    if current_user.is_authenticated:  
        return redirect(url_for('user_dashboard'))


    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if not user:
            flash('No account found with this email address. Please register first.', 'danger')
            return redirect(url_for('login'))

        db.session.refresh(user)  # Ensures we have the latest data from the DB

        if bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('user_dashboard'))
        else:
            print("Password did not match!")
            flash("Incorrect password.", "danger")

    return render_template('login.html', form=form)

# Route for google authorization
@app.route('/google-login', methods=['GET', 'POST'])
def googleLogin():
    #print("Session Before Authorize Redirect:", session)
    
    session.clear()
    print("Session After Clearing:", session)

    # Generate a unique nonce for this session and store it
    nonce = str(uuid.uuid4())
    session['nonce'] = nonce


    #print("Session After Authorize Redirect:", session)
    redirect_uri = url_for('googleCallback', _external=True)
    return oauth.myApp.authorize_redirect(redirect_uri, nonce=nonce)


# Route for google callback
@app.route('/google-sign-in', methods=['GET', 'POST'])
def googleCallback():
    # Retrieve the nonce from the session
    nonce = session.get('nonce')
    if not nonce:
        return redirect(url_for('googleLogin'))  # Redirect to login if nonce is missing

    # Exchange the authorization code for an access token
    token = oauth.myApp.authorize_access_token()

    try:
        # Parse the ID token and validate it with the stored nonce
        user_info = oauth.myApp.parse_id_token(token, nonce=nonce, leeway=120)
        session['user'] = user_info
    except ExpiredTokenError:
        print("The token has expired")
        return redirect(url_for('googleLogin'))  # Redirect if token is expired
    except JoseError as e:
        print(f"JoseError: {e}")
        return redirect(url_for('googleLogin'))  # Redirect for other token issues

    hashed_password = bcrypt.generate_password_hash(os.getenv('GOOGLE_PASSWORD')).decode('utf-8')

    # Debugging state and token
    print("Session State After OAuth:", session.get('state'))
    print("OAuth Token:", token)

    user_info = session.get('user')
    email = user_info['email']  # Correct the key access for email
    first_name = user_info['given_name']
    last_name = user_info['family_name']

    # Check if user already exists in the database
    user = User.query.filter_by(email=email).first()

    if user is None:
        # Create a new user
        new_user = User(email=email, first_name=first_name, last_name=last_name, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        user = new_user
    else:
        # Optionally update existing user details
        user.first_name = first_name
        user.last_name = last_name
        db.session.commit()
    
    login_user(user)
    return redirect(url_for("user_dashboard"))




# Route for registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        # Generate hashed password
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            password=hashed_password
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            
            #logs user in
            login_user(new_user)
            flash('Registration successful. You can now log in.', 'success')
            return redirect(url_for('user_dashboard'))
        except Exception as e:
            db.session.rollback()  # rollback in case of error
            flash(f"An error occurred: {e}", 'danger')
            print(f"Error occurred: {e}")

    return render_template('register.html', form=form)

@app.route('/user_dashboard', methods=['GET', 'POST'])
@login_required
def user_dashboard():
    # Get the user's email (from Google SSO or fallback to registered email)
    user = session.get('user')
  
    email = user.get('email') if user else current_user.email
    
    google_first_name = current_user.first_name

    cal_info = cal_json['data']
    upcoming_events = []
    past_events = []

    # Get current date and time
    now = datetime.now(timezone.utc)  # Make now timezone-aware


    # Loop through calendar data and filter events
    for item in cal_info:
        if 'bookingFieldsResponses' in item and 'email' in item['bookingFieldsResponses']:
            event_email = item['bookingFieldsResponses']['email']
            if event_email == email:
                start_time = datetime.fromisoformat(item['start'].replace('Z', '+00:00'))
                end_time = start_time + timedelta(minutes=item['duration'])


                event = {
                    'title': item['title'].split(' between ')[0],  
                    'status': item['status'].capitalize(),  
                    'start': start_time,
                    'end': end_time,
                    'start_time': start_time.strftime('%I:%M %p'),
                    'end_time': end_time.strftime('%I:%M %p'),
                    'day': start_time.day,
                    'month_abbreviation': start_time.strftime('%b'),
                    'event_type': item['eventType']['slug'],
                    'duration': item['duration'],
                    'time_zone': item['hosts'][0]['timeZone'],
                    'meeting_url': item['meetingUrl'],
                    'year': start_time.year,
                }

                # Categorize events
                if start_time >= now:
                    upcoming_events.append(event)
                else:
                    past_events.append(event)

    # Sort upcoming events (earliest first) and past events (latest first)
    upcoming_events.sort(key=lambda x: x['start'])
    past_events.sort(key=lambda x: x['start'], reverse=True)

    # Pagination setup
    page = request.args.get('page', 1, type=int)
    per_page = 8  

    def paginate(events):
        total = len(events)
        start = (page - 1) * per_page
        end = start + per_page
        total_pages = ceil(total / per_page)
        return events[start:end], total_pages

    paginated_upcoming, total_pages_upcoming = paginate(upcoming_events)
    paginated_past, total_pages_past = paginate(past_events)

    return render_template(
        'user_dashboard.html',
        google_email=email,
        upcoming_events=paginated_upcoming,
        past_events=paginated_past,
        sessionType=user,
        page=page,
        total_pages_upcoming=total_pages_upcoming,
        total_pages_past=total_pages_past,
        google_first_name=google_first_name
    )



@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    #session.pop("user", None)
    session.clear()
    return redirect(url_for('login'))

@app.route('/appointment-confirmed', methods=['GET', 'POST'])
def confirmAppt():
    return render_template('confirmAppt.html')




if __name__ == '__main__':
    app.run(debug=True)