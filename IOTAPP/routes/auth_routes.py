from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User
from utils import get_public_ip, log_activity, log_access_attempt, log_page_access

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']

        # Validate inputs
        if not username or not email or not password:
            flash('All fields are required.')
            return redirect(url_for('auth.register'))

        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('auth.register'))
        if User.query.filter_by(email=email).first():
            flash('Email already exists.')
            return redirect(url_for('auth.register'))

        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Create a new user
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. Please log in.')
        return redirect(url_for('auth.login'))

    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        ip_address = request.remote_addr
        log_page_access(user.username, 'Register', ip_address)

    return render_template('register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        ip_address = request.remote_addr

        # Validate inputs
        if not username or not password:
            flash('Username and password are required.')
            return redirect(url_for('auth.login'))

        # Fetch user from the database
        user = User.query.filter_by(username=username).first()

        # Check if user exists and password is correct
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_role'] = user.role
            log_activity(user.username, 'Login', ip_address)

            if user.role == 'Admin':
                return redirect(url_for('admin.admin_page'))
            else:
                return redirect(url_for('home.home'))
        else:
            log_access_attempt(username, ip_address)
            flash('Invalid username or password.')
            return redirect(url_for('auth.login'))

    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:  # Ensure user exists before logging page access
            ip_address = request.remote_addr
            log_page_access(user.username, 'Login', ip_address)
        else:
            # Clear invalid session and redirect to login
            session.clear()
            flash('Session is invalid. Please log in again.')
            return redirect(url_for('auth.login'))

    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        ip_address = get_public_ip()
        log_activity(user.username, 'Logout', ip_address)
        log_page_access(user.username, 'Logout', ip_address)
        session.pop('user_id', None)
        session.pop('user_role', None)
    return redirect(url_for('home.index'))