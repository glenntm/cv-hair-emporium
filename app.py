from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

if __name__ == '__main__':
    app.run(debug=True)

# Dummy data for demonstration
appointments = []
gallery_items = [
    {"type": "Haircut", "image": "haircut1.jpg", "description": "Stylish haircut"},
    {"type": "Hair Color", "image": "color1.jpg", "description": "Beautiful hair color"}
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

if __name__ == '__main__':
    app.run(debug=True)
