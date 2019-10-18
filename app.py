from flask import Flask, session, redirect, render_template, request, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func #to allow auto time stamp
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, login_required
from flask_security.utils import hash_password
import re

app = Flask(__name__)
app.secret_key = "Sp00kY"
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///photobomb.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECURITY_PASSWORD_SALT'] = ""
db = SQLAlchemy(app)
migrate = Migrate(app, db)
security = Security()

roles_users = db.Table('roles_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

# Create a user to test with
# @app.before_first_request
# def create_user():
#     db.create_all()
#     user_datastore.create_user(email='matt@nobien.net', password='password')
#     db.session.commit()

# Views
# @app.route('/')
# def home():
#     return render_template('index.html')

@app.route("/register", methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        user_datastore.create_user(
                                email=request.form.get('email'),
                                password=hash_password(request.form.get('password')))
        db.session.commit()
        return redirect(url_for('profile'))

    return render_template('home.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/home')


if __name__ == "__main__":
    app.run(debug=True)