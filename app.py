from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy 
from flask_migrate import Migrate
from flask_login import UserMixin
from secret import database_username, database_secret, databse_name, databse_password


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{database_username}:{databse_password}@localhost:5432/{databse_name}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = f'{database_secret}'
db = SQLAlchemy(app)

if __name__ == '__main__':
    app.run(debug=True)

migrate = Migrate(app, db)


# Dummy data for demonstration
appointments = []
gallery_items = [
    {"type": "Haircut", "image": "haircut1.jpg", "description": "Stylish haircut"},
    {"type": "Hair Color", "image": "color1.jpg", "description": "ok hair color"}
]
reviews = []

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

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')