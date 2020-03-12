import os
from flask import Flask, render_template, redirect, request, url_for, flash
from flask_pymongo import PyMongo
from flask_sqlalchemy import SQLAlchemy
from bson.objectid import ObjectId 
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required

app = Flask(__name__)
app.config["MONGO_DBNAME"] = 'travel'
app.config["MONGO_URI"] = 'mongodb+srv://root:Johann@myfirstcluster-ugp0n.mongodb.net/travel?retryWrites=true&w=majority'
bcrypt = Bcrypt(app)
mongo = PyMongo(app)
app.secret_key = "cachimiro"
app.config['SQLAlCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'Login'
login_manager.login_message_category = 'info'


#this code is for a decorative fuction
@login_manager.user_loader
def load_user(user_id):
    return user.query.get(int(user_id))
# this class is for the storege/Database  user
# for my loging/ register system


class user(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    image = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)

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

    def validation_username(self, username):
        Users = user.query.filter_by(username=username.data).first() 
        if Users:
            raise ValidationError('That username is taken please use another one')

    def validation_email(self, email):
        Users = user.query.filter_by(email=email.data).first() 
        if Users:
            raise ValidationError('That email is taken please use another one')
    


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
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = registrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        User = user(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(User)
        db.session.commit()
        flash(f'An Account has been created for {form.username.data}!', 'success')
        return redirect(url_for('Login'))
    return render_template('register.html', title="Register", form=form)

# code for the login page 
@app.route('/login',  methods=['GET', 'POST'])
def Login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = loginForm()
    if form.validate_on_submit():
        userr = user.query.filter_by(email=form.email.data).first()
        if userr and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            #here i am using a terminary conditional
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('wrong login check Email or Password', 'danger')
    return render_template('login.html', title="Login", form=form)


#logout function
@app.route('/logout')
def Logout():
    logout_user()
    return redirect(url_for('index'))


#this line of code will be for the accounts
@app.route('/accounts')
@login_required
def accounts():
    return render_template('acount.html', title="Account", form=form)


if __name__ == '__main__':
    app.run(host=os.environ.get('IP'),
            port=int(os.environ.get('PORT')),
            debug=True)