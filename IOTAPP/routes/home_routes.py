from flask import Blueprint, render_template, session, redirect, url_for, flash, request, jsonify
from utils import log_activity, get_public_ip
from models import User, db, Activity, AccessLog

home_bp = Blueprint('home', __name__)

@home_bp.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        ip_address = get_public_ip()  
        log_activity(user.username, 'Index', ip_address)
    return render_template('index.html')

@home_bp.route('/home')
def home():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            ip_address = get_public_ip()  
            log_activity(user.username, 'Home', ip_address)
            return render_template('index.html', user=user)  
    else:
        flash('You need to log in first.')
        return redirect(url_for('auth.login'))

