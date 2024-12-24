from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, json
from flask_sqlalchemy import SQLAlchemy 
from flask_migrate import Migrate
from flask_login import login_user, LoginManager, login_required, logout_user, current_user
from secret import database_username, database_secret, databse_name, databse_password, google_client_ID, google_client_secret, flask_secret,google_password, cal_bearer_token, gmail_password, crsf_secret
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, Form, validators
from wtforms.validators import InputRequired,Length, ValidationError,DataRequired, Email, length, Regexp
from models import User, db, connect_db
from flask_bcrypt import Bcrypt
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
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import secrets 



app = Flask(__name__)
json = FlaskJSON(app)
bcrypt = Bcrypt(app)
mail = Mail(app) # instantiate the mail class 

#for CSRF token
app.config['SECRET_KEY'] = crsf_secret


# configuration of mail 
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'danotoriousg@gmail.com'
app.config['MAIL_PASSWORD'] = gmail_password
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app) 


#database setup
app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{database_username}:{databse_password}@localhost:5432/{databse_name}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = f'{database_secret}'

connect_db(app)


db_host = 'localhost'
db_port = '5432'  # Default PostgreSQL port
db_name = databse_name
db_user = database_username
db_password = databse_password
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
    "OAUTH2_CLIENT_ID": f"{google_client_ID}",
    "OAUTH2_CLIENT_SECRET": f"{google_client_secret}",
    "OAUTH_META_URL": "https://accounts.google.com/.well-known/openid-configuration",
    "FLASK_SECRET": f"{flask_secret}",
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
    "Authorization": f"{cal_bearer_token}"
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
            msg = Message('Password Reset Request',
            sender ='danotoriousg@gmail.com', 
                          recipients=[email],
                          body=f'Click the link to reset your password: {reset_url}')
            mail.send(msg)
            flash('Password reset email sent. Check your inbox.', 'info')
            return render_template('gallery.html')
        else:
            flash('Email not found.', 'warning')
            return render_template('forgotPw.html', form=form)
   #below sends gmail message
   '''
      msg = Message( 
                'Hello', 
                sender ='danotoriousg@gmail.com', 
                recipients = ['glenntm1@live.com'] 
               ) 
   msg.body = 'Hello Flask message sent from Flask-Mail'
   mail.send(msg) 
   flash('Sent')
   '''
   return render_template('forgotPw.html', form=form)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    form = LoginForm()
    user = User.query.filter_by(reset_token=token).first()
    if not user or user.token_expiration < datetime.now():
        return "Token is invalid or expired."
    
    if request.method == 'POST':
        new_password = request.form['password']
        print(f"New password: {new_password}")  # Debugging
        user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        print(f"New hashed password: {user.password}")  # Debugging
        user.reset_token = None
        user.token_expiration = None
        
        try:
            db.session.commit()
            print("Password hash updated successfully.")
        except Exception as e:
            db.session.rollback()  # Rollback in case of an error
            print(f"Error updating password: {e}")
            return "An error occurred while updating your password."

        return "Password successfully reset."   
    
    return render_template('resetPw.html', form=form, token=token)

@app.route('/')
def home():
    appointments = cal_json['data']

    return render_template('home.html', cal_url = response.text, appointments=appointments)

@app.route('/gallery')
def gallery():
    return render_template('gallery.html')

@app.route('/reviews', methods=['GET', 'POST'])
def reviews_page():
    if request.method == 'POST':
        review = {
            "name": request.form['name'],
            "review": request.form['review']
        }
        reviews.append(review)
        return redirect(url_for('reviews_page'))
    return render_template('reviews.html', reviews=reviews)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        #check if there is an email in database 
        if not user:
            flash('No account found with this email address. Please register first.', 'danger')
            return redirect(url_for('login'))

        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('user_dashboard'))
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

    hashed_password = bcrypt.generate_password_hash(google_password).decode('utf-8')

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
    # Check if 'user' exists in session
    user = session.get('user')
    if user:
        # Google SSO email
        email = user.get('email')  # Get the email from Google session
    else:
        # Fallback to the email captured during registration
        # Assuming 'current_user' contains the registered user's details
        email = current_user.email  # Use your ORM model or context to fetch

    # Debugging print
    print(f"Email used: {email}")

    cal_info = cal_json['data']
    matching_events = []

    # Loop through cal_json and collect all matches based on the email in bookingFieldsResponses
    for item in cal_info:
        if 'bookingFieldsResponses' in item and 'email' in item['bookingFieldsResponses']:
            event_email = item['bookingFieldsResponses']['email']
            # Only add events where the attendee's email matches the logged-in user's email
            if event_email == email:
                # Parse the start date
                start_time = datetime.fromisoformat(item['start'].replace('Z', '+00:00'))
                
                # Calculate the end time by adding the duration to the start time
                end_time = start_time + timedelta(minutes=item['duration'])

                # Format the start time, end time, and other fields
                event = {
                    'title': item['title'].split(' between ')[0],  # Extracting the part before "between"
                    'status': item['status'].capitalize(),  # Capitalizing the status
                    'start': start_time,
                    'end': end_time,
                    'start_time': start_time.strftime('%I:%M %p'),  # 12-hour format with AM/PM
                    'end_time': end_time.strftime('%I:%M %p'),  # End time in 12-hour format
                    'day': start_time.day,
                    'month_abbreviation': start_time.strftime('%b'),  # Abbreviated month (e.g., "Oct")
                    'event_type': item['eventType']['slug'],
                    'duration': item['duration'],
                    'time_zone': item['hosts'][0]['timeZone'],  # Assuming timeZone is in hosts
                    'meeting_url': item['meetingUrl'],
                    "year": start_time.year,
                }
                matching_events.append(event)

    # Sort the events by start time in descending order
    matching_events.sort(key=lambda x: x['start'], reverse=True)

    # Debugging print
    print(f"Session user: {session.get('user')}")

    return render_template(
        'user_dashboard.html',
        google_email=email,
        matching_events=matching_events,
        sessionType=user,
        cal_response=response.text
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