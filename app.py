from flask import Flask, render_template, url_for
from flask_navigation import Navigation
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError

# import sqlite3

app = Flask(__name__)
nav = Navigation(app)

db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"
app.config['SECRET_KEY'] = "thisisasecretkey"

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
	return render_template("index.html")
	
@app.route("/poems")
def poems():
	return render_template("poems.html")
	
@app.route("/authors")
def authors():
	return render_template("authors.html")

@app.route("/login")
def login():
	return render_template("login.html")

@app.route("/register")
def register():
	return render_template("register.html")

if __name__ == '__main__':
    app.run(debug=True)