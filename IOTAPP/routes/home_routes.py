from flask import Blueprint, render_template, session, redirect, url_for, flash, request
from utils import scan_wifi_networks, scan_smart_devices, log_activity, get_public_ip
from models import User, db, Activity, AccessLog

home_bp = Blueprint('home', __name__)

@home_bp.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        ip_address = get_public_ip()  # Use get_public_ip() to get the correct IP
        log_activity(user.username, 'Index', ip_address)
    return render_template('index.html')

@home_bp.route('/home')
def home():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        ip_address = get_public_ip()  # Use get_public_ip() to get the correct IP
        log_activity(user.username, 'Home', ip_address)
        return render_template('home.html', user=user)
    else:
        flash('You need to log in first.')
        return redirect(url_for('auth.login'))

@home_bp.route('/scan_wifi', methods=['POST'])
def scan_wifi():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        ip_address = get_public_ip()  # Use get_public_ip() to get the correct IP
        log_activity(user.username, 'Scan Wi-Fi', ip_address)
        networks = scan_wifi_networks()
        return render_template('home.html', networks=networks)
    else:
        flash('You need to log in first.')
        return redirect(url_for('auth.login'))

@home_bp.route('/scan_network', methods=['POST'])
def scan_network():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        ip_address = get_public_ip()  # Use get_public_ip() to get the correct IP
        log_activity(user.username, 'Scan Network', ip_address)
        devices = scan_smart_devices()
        return render_template('home.html', devices=devices)
    else:
        flash('You need to log in first.')
        return redirect(url_for('auth.login'))