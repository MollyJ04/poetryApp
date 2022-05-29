import re
from flask import Flask, render_template, url_for, redirect, session, request, flash
from flask_navigation import Navigation
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
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
	comments = db.relationship('Comment',backref='user',passive_deletes=True)
	annotations = db.relationship('Annotation',backref='user',passive_deletes=True)

class Comment(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	text = db.Column(db.Text, nullable=False)
	date_created = db.Column(db.DateTime(timezone=True), default=func.now())
	poem = db.Column(db.Text)
	author = db.Column(db.Integer, db.ForeignKey('user.id',ondelete="CASCADE"), nullable=False)

class Annotation(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	text = db.Column(db.Text, nullable=False)
	date_created = db.Column(db.DateTime(timezone=True), default=func.now())
	poem = db.Column(db.Text)
	line = db.Column(db.Integer)
	author = db.Column(db.Integer, db.ForeignKey('user.id',ondelete="CASCADE"), nullable=False)

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

# class SearchForm(FlaskForm):
# 	searched = StringField("Searched")
# 	submit = SubmitField("Submit")

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
	# poemAuthors = {}
	# for i in poems:
	# 	response = requests.get(f"https://poetrydb.org/title/{i}:abs")
	# 	response = response.json()
	# 	author = response[0]["author"]
	# 	poemAuthors[i] = author
	return render_template("poems.html", poems=poems)
	
@app.route("/authors")
def authors():
	response = requests.get("https://poetrydb.org/author")
	response = response.json()
	authors = response["authors"]
	return render_template("authors.html", authors=authors)

@app.route("/read/<title>")
def read(title):
	response = requests.get(f"https://poetrydb.org/title/{title}:abs")
	response = response.json()
	# slight problem of that if there are multiple poems with the same name
	# this only takes first one
	# but we'll cross that bridge when we get there :)
	# if len(response)>1:
	# 	for i in response:
	# 		if i[""]
	poem = response[0]["lines"]
	author = response[0]["author"]
	comments = Comment.query.filter_by(poem=title)
	annotations = Annotation.query.filter_by(poem=title)
	isAnnotated = []
	for i in range(len(poem)):
		isAnnotated.append(False)
	for i in annotations:
		isAnnotated[i.line]=True
	print(isAnnotated,flush=True)
	return render_template("read.html",title=title,poem=poem,author=author,comments=comments,length=len(poem),annotations=annotations,isAnnotated=isAnnotated)

@app.route("/authorPoems/<author>")
def authorPoems(author):
	response = requests.get(f"https://poetrydb.org/author/{author}")
	response = response.json()
	poems = []
	for i in response:
		poems.append(i["title"])
	return render_template("authorPoems.html",poems=poems,author=author)

@app.route("/login", methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user:
			if bcrypt.check_password_hash(user.password, form.password.data):
				login_user(user)
				return redirect(url_for('dashboard'))
				# return redirect(url_for('dashboard',username=form.username.data))
	return render_template("login.html", form=form)

@app.route("/dashboard", methods=['GET', 'POST'])
@login_required
def dashboard():
	# user_id = session["user_id"]
	# return render_template("dashboard.html", variable=user_id)
	return render_template("dashboard.html")

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

@app.route("/create-comment/<title>", methods=['POST'])
@login_required
def create_comment(title):
	text = request.form.get('text')
	comment = Comment(text=text,author=current_user.id,poem=title)
	db.session.add(comment)
	db.session.commit()
	return redirect(url_for('read',title=title))

@app.route("/create-annotation/<title>/<line>", methods=['POST'])
@login_required
def create_annotation(title,line):
	text = request.form.get('text')
	if len(text.strip()) != 0:
		annotation = Annotation(text=text,author=current_user.id,poem=title,line=line)
		db.session.add(annotation)
		db.session.commit()
	return redirect(url_for('read',title=title))

@app.route("/delete-comment/<title>/<comment_id>")
@login_required
def delete_comment(title,comment_id):
	comment = Comment.query.filter_by(id=comment_id).first()
	# ignored the if statements in tutorial to check that you're allowed to delete
	# should probably add those back later
	db.session.delete(comment)
	db.session.commit()
	return redirect(url_for('read',title=title))

@app.route("/delete-annotation/<title>/<annotation_id>")
@login_required
def delete_annotation(title,annotation_id):
	annotation = Annotation.query.filter_by(id=annotation_id).first()
	db.session.delete(annotation)
	db.session.commit()
	return redirect(url_for('read',title=title))

@app.route("/search", methods=['GET','POST'])
def search():
	# form = SearchForm()
	# if form.validate_on_submit():
	# 	searchTerm = form.searched.data
	searchTerm = request.form.get('search')
	poemResults = requests.get(f"https://poetrydb.org/title/{searchTerm}")
	poemResults = poemResults.json()
	poems = []
	if type(poemResults) is dict:
		poems.append("none")
	elif type(poemResults) is list:
		for i in poemResults:
			poems.append(i["title"])

	authorResults = requests.get(f"https://poetrydb.org/author/{searchTerm}")
	authorResults = authorResults.json()
	authors = []
	if type(authorResults) is dict:
		authors.append("none")
	elif type(authorResults) is list:
		for i in authorResults:
			if i["author"] not in authors:
				authors.append(i["author"])
	return render_template("search.html",poemResults=poemResults,authorResults=authorResults,term=searchTerm,poems=poems,authors=authors)

if __name__ == '__main__':
    app.run(debug=True)