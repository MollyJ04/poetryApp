import re
from flask import Flask, render_template, url_for, redirect, session
from flask_navigation import Navigation
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
# import urllib3
import json
import requests

# import sqlite3

app = Flask(__name__)
nav = Navigation(app)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"
app.config['SECRET_KEY'] = "thisisasecretkey"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))

class User(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(20), nullable=False, unique=True)
	password = db.Column(db.String(80), nullable=False)

class RegisterForm(FlaskForm):
	username = StringField(validators=[InputRequired(), Length(
		min=4, max=20)], render_kw={"placeholder": "Username"})
	password = PasswordField(validators=[InputRequired(), Length(
		min=4, max=20)], render_kw={"placeholder": "Password"})
	submit = SubmitField("Register")
	def validate_username(self, username):
		existing_user_username = User.query.filter_by(
			username=username.data).first()
		if existing_user_username:
			raise ValidationError(
				"That username already exists. Please choose a different one.")

class LoginForm(FlaskForm):
	username = StringField(validators=[InputRequired(), Length(
		min=4, max=20)], render_kw={"placeholder": "Username"})
	password = PasswordField(validators=[InputRequired(), Length(
		min=4, max=20)], render_kw={"placeholder": "Password"})
	submit = SubmitField("Login")

# db = sqlite3.connect(poetryApp.db)

nav.Bar('top', [
	nav.Item('Home', 'index'),
	nav.Item('Poems', 'poems'),
	nav.Item('Authors', 'authors')])

@app.route("/")
def index():
	response = requests.get("https://poetrydb.org/random")
	response = response.json()
	title = response[0]["title"]
	author = response[0]["author"]
	poem = response[0]["lines"]
	return render_template("index.html",title=title,author=author,poem=poem)
	
@app.route("/poems")
def poems():
	response = requests.get("https://poetrydb.org/title")
	response = response.json()
	poems = response["titles"]
	titles = []
	for i in poems:
		newTitle = re.sub(r'\W+', ' ', i)
		titles.append(newTitle.strip())
	return render_template("poems.html", poems=poems)
	
@app.route("/authors")
def authors():
	return render_template("authors.html")

@app.route("/read/<title>")
def read(title):
	response = requests.get(f"https://poetrydb.org/title/{title}")
	response = response.json()
	# slight problem of that if there are multiple poems with the same name
	# this only takes first one
	# but we'll cross that bridge when we get there :)
	poem = response[0]["lines"]
	return render_template("read.html",title=title,poem=poem)

@app.route("/login", methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user:
			if bcrypt.check_password_hash(user.password, form.password.data):
				login_user(user)
				return redirect(url_for('dashboard'))
	return render_template("login.html", form=form)

@app.route("/dashboard", methods=['GET', 'POST'])
@login_required
def dashboard():
	user_id = session["user_id"]
	return render_template("dashboard.html", variable=user_id)

@app.route("/logout", methods=['GET', 'POST'])
@login_required
def logout():
	logout_user()
	return redirect(url_for('login'))

@app.route("/register", methods=['GET', 'POST'])
def register():
	form = RegisterForm()

	if form.validate_on_submit():
		hashed_password = bcrypt.generate_password_hash(form.password.data)
		new_user = User(username=form.username.data, password=hashed_password)
		db.session.add(new_user)
		db.session.commit()
		return redirect(url_for('login'))

	return render_template("register.html", form=form)

if __name__ == '__main__':
    app.run(debug=True)