import os
import env
from flask import Flask, render_template, redirect, request, url_for, flash
from flask_pymongo import PyMongo
from flask_sqlalchemy import SQLAlchemy
from bson.objectid import ObjectId 
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import (DataRequired, Length, Email,
                                EqualTo, ValidationError)
from flask_login import (LoginManager, UserMixin, login_user,
                         current_user, logout_user, login_required)
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_mail import Mail, Message

app = Flask(__name__)
app.config["MONGO_DBNAME"] = 'travel'
app.config["MONGO_URI"] = 'mongodb+srv://root:Johann@myfirstcluster-ugp0n.mongodb.net/travel?retryWrites=true&w=majority'
bcrypt = Bcrypt(app)
mongo = PyMongo(app)
app.secret_key = "cachimiro"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'Login'
login_manager.login_message_category = 'info'
app.config['MAIL_SERVER'] = 'sntp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_ADD')
app.config['MAIL_USERNAME'] = os.environ.get('PASSWORD')
mail = Mail(app)


#this code is for a decorative fuction
@login_manager.user_loader
def load_user(user_id):
    return user.query.get(int(user_id))
# this class is for the storege/Database  user
# for my loging/ register system


class user(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

#this line if code is fo the password reset 
    def get_reset_token(self, user, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['secret_key'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return user.query.get(user_id)
    

    def __repr__(self):
        return f"user('{self.username}', '{self.email}')"

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

    def validate_username(self, username):
        User = user.query.filter_by(username=username.data).first()
        if User:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        User = user.query.filter_by(email=email.data).first()
        if User:
            raise ValidationError('That email is taken. Please choose a different one.')

# class for login form 

class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


#forms for reset password
class resetForm(FlaskForm):
    email = StringField('Email',
                         validators=[DataRequired(), Email()])
    submit = SubmitField('Get a New password')

    def validate_email(self, email):
        User = user.query.filter_by(email=email.data).first()
        if User is None:
            raise ValidationError('There is no Account! with that email please register')

class resetPasswordForm(FlaskForm):
    password = PasswordField('password',
                              validators=[DataRequired()])
    password_repeat = PasswordField('Confirm password',
                                     validators=[DataRequired(), EqualTo('password')])

    submit = SubmitField('New password')
  

#code for index.html
@app.route('/')
def index():
    
    return render_template("index.html", Travel=mongo.db.pais.find())

#code for adding information to the index.html
@app.route('/add_travel_info')
@login_required
def add_information_for_travel():
    return render_template('add-info-travel.html')

     
@app.route('/add_review', methods=['POST'])
@login_required
def insert_reviews():
    travel = mongo.db.pais
    travel.insert_one(request.form.to_dict())
    flash('your Post has been uploaded succesfully', 'info')
    return redirect(url_for('index'))



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
@app.route("/login", methods=['GET', 'POST'])
def Login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        User = user.query.filter_by(email=form.email.data).first()
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        if User and bcrypt.check_password_hash(hashed_password, form.password.data):
            login_user(User, remember=form.remember.data)
            flash('you have been succefully logged in', 'primary')
            return redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)



#logout function
@app.route('/logout')
def Logout():
    logout_user()
    flash('you have been succefully logged out', 'primary')
    return redirect(url_for('index'))


#this line of code will be for the accounts
@app.route('/accounts')
@login_required
def accounts():
    return render_template('account.html', title="Account")


#this code will sned reset emails to the user
def send_reset_email(user):
    token = user.get_reset_token('self')
    msg = Message('Password Reset Request',
                  sender='noreply@demo.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)


#this code is for the password reset
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = resetForm()
    if form.validate_on_submit():
        User = user.query.filter_by(email=form.email.data).first()
        send_reset_email(User)
        flash('An email has been sent to the email registered with you instructions to reset passwors', 'info')
        return redirect(url_for('Login'))
    return render_template('reset.html', form=form)


#this code will make sure the user is the right one and it will reset the link/token
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    User = user.verify_reset_token(token)
    if not User:
        flash('that link is invalid or expired', 'warning')
        return redirect(url_for('reset_request'))
    form = resetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        User.password = hashed_password
        db.session.commit()
        flash(f'your passwword has been updated now ypu are able to log in!', 'success')
        return redirect(url_for('Login'))
    return render_template('reset-link.html', form=form)


if __name__ == '__main__':
    app.run(host=os.environ.get('IP'),
            port=int(os.environ.get('PORT')),
            debug=True)