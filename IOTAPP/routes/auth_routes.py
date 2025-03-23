from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from models import db, User
from utils import get_public_ip, log_activity, log_access_attempt, log_page_access

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('auth.login'))
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        ip_address = request.remote_addr
        log_page_access(user.username, 'Register', ip_address)
    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip_address = get_public_ip()
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session['user_id'] = user.id
            session['user_role'] = user.role
            log_activity(user.username, 'Login', ip_address)
            if user.role == 'Admin':
                return redirect(url_for('admin.admin_page'))
            else:
                return redirect(url_for('home.home'))
        else:
            log_access_attempt(username, ip_address)
            flash('Invalid credentials.')
            return redirect(url_for('auth.login'))
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        ip_address = request.remote_addr
        log_page_access(user.username, 'Login', ip_address)
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
    return redirect(url_for('auth.login'))