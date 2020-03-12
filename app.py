import os
from flask import Flask, render_template, redirect, request, url_for, flash
from flask_pymongo import PyMongo
from flask_sqlalchemy import SQLAlchemy
from bson.objectid import ObjectId 
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo

app = Flask(__name__)
app.config["MONGO_DBNAME"] = 'travel'
app.config["MONGO_URI"] = 'mongodb+srv://root:Johann@myfirstcluster-ugp0n.mongodb.net/travel?retryWrites=true&w=majority'
bcrypt = Bcrypt(app)
mongo = PyMongo(app)
app.secret_key = "cachimiro"
app.config['SQLAlCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
# this class is for the storege od user
# for my loging/ register system
class user(db.Model):
    id = db.Column(db.integer, primary_key=True)
    username = db.Column(db.string(15), unique=True, nullable=False)
    email = db.Column(db.string(100), unique=True, nullable=False)
    image = db.Column(db.string(20), nullable=False, default='default.jpg')
    password = db.Column(db.string(60), nullable=False)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image}')"
# class for for the registration form


class registrationForm(FlaskForm):
    username = StringField('username',
                            validators=[DataRequired(), Length(min=1, max=15)])
    email = StringField('Email',
                         validators=[DataRequired(), Email()])
    password = PasswordField('password',
                              validators=[DataRequired()])
    password_repeat = PasswordField('Confirm password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')


# class for login form 

class loginForm(FlaskForm):

    email = StringField('Email',
                         validators=[DataRequired(), Email()])
    password = PasswordField('password',
                              validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


@app.route('/')
def index():
    return render_template("index.html", Travel=mongo.db.pais.find())


# this line of code is for my registration form
@app.route('/register', methods=['GET', 'POST'])
def registration():
    form = registrationForm()
    if form.validate_on_submit():
        flash(f'An Account has been created for {form.username.data}!', 'success')
        return redirect(url_for('index'))
    return render_template('register.html', title="Register", form=form)

# code for the login page 
@app.route('/login',  methods=['GET', 'POST'])
def Login():
    form = loginForm()
    if form.validate_on_submit():
        if form.email.data == 'johannaguirre55@gmail.com' and form.password.data == "1234":
            flash('you have been logged in!', 'success')
            return redirect(url_for('index'))
        else:
            flash('wrong log in check user name or password', 'danger')
    return render_template('login.html', title="Login", form=form)


"""
this lines of code are for the user to create or log in to the system

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = registrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations your account has now been create', 'success')
        return redirect(url_for('login'))

"""

if __name__ == '__main__':
    app.run(host=os.environ.get('IP'),
            port=int(os.environ.get('PORT')),
            debug=True)