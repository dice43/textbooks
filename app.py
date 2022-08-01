from flask import Flask, render_template, url_for, flash, redirect, request
from forms import RegistrationForm, TextSearchForm
from login import LoginForm
from flask_behind_proxy import FlaskBehindProxy
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import requests

app = Flask(__name__)                    # this gets the name of the file so Flask knows it's name
proxied = FlaskBehindProxy(app)  ## add this line
bcrypt = Bcrypt(app)             # code to create bcrypt wrapper for flask app
app.config['SECRET_KEY'] = '39e544a7b87e65b3d845915b1533104f'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
name = None

class User(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(20), unique=True, nullable=False)
  email = db.Column(db.String(120), unique=True, nullable=False)
  password = db.Column(db.String(60), nullable=False)

  def __repr__(self):
    return f"User('{self.username}', '{self.email}')"

class Books(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    isbn = db.Column(db.String(13), nullable=False)
    email = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f"User with email('{self.email}') has saved a textbook with an isbn number of('{self.isbn}')"

@app.route("/", methods=['GET', 'POST'])                          # this tells you the URL the method below is related to
def home():
    search = TextSearchForm(request.form)
    if request.method == "POST":
        return results(search)

    return render_template('home.html', subtitle='Welcome to Student-Xchange', text='Browse for textbooks')      # this prints HTML to the webpage

@app.route("/second_page")
def second_page():
    return render_template('second_page.html', subtitle='Second Page', text='This is the second page')

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit(): # checks if entries are valid
        if form.validate_on_submit():
            pw_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=form.username.data, email=form.email.data, password=pw_hash)
            db.session.add(user)
            db.session.commit()
        flash(f'Account created for {form.username.data}!', 'success')
        return redirect(url_for('home')) # if so - send to home page
    return render_template('register.html', title='Register', form=form)
@app.route("/login", methods=['GET', 'POST'])
def login():
    login = LoginForm()
    if login.validate_on_submit(): # checks if entries are valid
        if login.validate_on_submit():
            login_username = login.username.data
            login_pass = login.password.data
            query_username = User.query.filter_by(username=login_username).first()
            query_email = User.query.filter_by(email=login_username).first()
            if query_username or query_email:
                global name
                if query_username:
                    hash_pass = query_username.password
                    if not bcrypt.check_password_hash(hash_pass, login_pass):
                        flash('You have input the incorrect login information or password')
                    else:
                        flash('You have successfully logged in')
                        name = login_username
                        
                        return redirect(url_for('user'))
                if query_email:
                    hash_pass = query_email.password
                    if not bcrypt.check_password_hash(hash_pass, login_pass):
                        flash('You have input the incorrect login information or password')
                    else:
                        flash('You have successfully logged in')
                        name = query_email.username
                        return redirect(url_for('user'))
            else:
                flash('You have input the incorrect login information or password')
    return render_template('signin.html', title='Log In', form=login)
@app.route("/user", methods=['GET','POST'])
def user():
    search = TextSearchForm(request.form)
    if request.method == "POST":
        return results(search)

    subtitle = ''
    text = ''

    if name is None:
        subtitle = 'Hello User'
        text = 'You have not logged in to the user page'
    else:
        subtitle = f'Hello {name}'
        text = 'You are logged in to the user page! Search for textbooks below'
    return render_template('user_page.html', subtitle=subtitle, text=text)
@app.route("/results", methods=["POST"])
def results(search):
    isbn = request.form["isbn"] 
    #link = "https://openlibrary.org/isbn/"
    #data = requests.get(link + isbn + ".json").json()   
    link = f"https://openlibrary.org/api/books?bibkeys=ISBN:{isbn}&jscmd=data&format=json"
    data = requests.get(link).json()[f'ISBN:{isbn}']
    subtitle = f"Search results for {data['title']}"
    
    imgPath = None
    try:
        imgPath = data['cover']['large']
    except:
        imgPath = "https://via.placeholder.com/200x300"
    return render_template('results.html', subtitle=subtitle, bookInfo=data, img=imgPath, isbn=isbn)
@app.route("/save", methods=["POST"])
def save_to_database():

    saved_book = request.form["saveBtn"]

    if name is None:
        return redirect(url_for("login"))
    else:
        current_user = User.query.filter_by(username=name).first()
        book = Books(isbn=saved_book, email=current_user.email)
        db.session.add(book)
        db.session.commit()

    return render_template("saved.html")
if __name__ == '__main__':               # this should always be at the end
    app.run(debug=True, host="0.0.0.0")