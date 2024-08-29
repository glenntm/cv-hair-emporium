from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy 
from flask_migrate import Migrate
from flask_login import UserMixin
from secret import database_username, database_secret, databse_name, databse_password
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, Form
from wtforms.validators import InputRequired,Length, ValidationError,DataRequired, Email
from models import User
from flask_bcrypt import Bcrypt
import psycopg2
from psycopg2 import sql


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{database_username}:{databse_password}@localhost:5432/{databse_name}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = f'{database_secret}'
db = SQLAlchemy(app)

db_host = 'localhost'
db_port = '5432'  # Default PostgreSQL port
db_name = databse_name
db_user = database_username
db_password = databse_password
bcrypt = Bcrypt(app)


migrate = Migrate(app, db)


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


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/book', methods=['GET', 'POST'])
def book():
    if request.method == 'POST':
        appointment = {
            "name": request.form['name'],
            "service": request.form['service'],
            "date": request.form['date'],
            "time": request.form['time']
        }
        appointments.append(appointment)
        return redirect(url_for('home'))
    return render_template('book.html')

@app.route('/gallery')
def gallery():
    return render_template('gallery.html', gallery_items=gallery_items)

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
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(email=form.email.data, password=hashed_password, first_name=form.first_name.data, last_name=form.last_name.data).decode('utf-8')
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)