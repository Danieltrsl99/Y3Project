from flask import Blueprint, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User
from utils import getIP, log_activity, log_access_attempt, log_page_access
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
from models import User

authblue = Blueprint('auth', __name__)
limiter = Limiter(get_remote_address, app=None, default_limits=["5 per minute"])


def is_valid_email(email):
    """Validate email format."""
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email)

def is_valid_username(username):
    """Validate username format (alphanumeric only, 3-20 characters)."""
    return re.match(r'^[a-zA-Z0-9]{3,20}$', username)

@authblue.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']

       
        if not username or not email or not password:#validate input
            return redirect(url_for('auth.register'))

        if not is_valid_username(username):
            return redirect(url_for('auth.register'))

        if not is_valid_email(email):
            return redirect(url_for('auth.register'))

        if len(password) < 8: #passsword length min 8
            return redirect(url_for('auth.register'))

        
        if User.query.filter_by(username=username).first(): # Check for existing user
            return redirect(url_for('auth.register'))
        if User.query.filter_by(email=email).first():
            return redirect(url_for('auth.register'))

     
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')#hash the password

        new_user = User(username=username, email=email, password=hashed_password)#adds new user 

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('auth.login'))

    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        ip_address = request.remote_addr
        log_page_access(user.username, 'Register', ip_address)

    return render_template('register.html')


@authblue.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        ip_address = request.remote_addr

       
        if not username or not password:
            return redirect(url_for('auth.login'))

        if not is_valid_username(username):
            return redirect(url_for('auth.login'))

        user = User.query.filter_by(username=username).first()#check for user 

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_role'] = user.role
            log_activity(user.username, 'Login', ip_address)

            if user.role == 'Admin':
                return redirect(url_for('admin.admin_page')) #if admin user logs in they can access admin
            else:
                return redirect(url_for('home.home'))
        else:
            log_access_attempt(username, ip_address)
            return redirect(url_for('auth.login'))

    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:  
            ip_address = request.remote_addr
            log_page_access(user.username, 'Login', ip_address)
        else:
            session.clear()
            return redirect(url_for('auth.login'))

    return render_template('login.html')

@authblue.route('/logout')
def logout():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        ip_address = getIP()
        log_activity(user.username, 'Logout', ip_address)
        
        session.pop('user_id', None)
        session.pop('user_role', None)
    return redirect(url_for('home.index'))