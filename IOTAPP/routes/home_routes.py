from flask import Blueprint, render_template, session, redirect, url_for, flash, request, jsonify
from utils import scan_wifi_networks, scan_smart_devices, log_activity, get_public_ip
from models import User, db, Activity, AccessLog, UserDevices

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
        if user:
            ip_address = get_public_ip()  # Use get_public_ip() to get the correct IP
            log_activity(user.username, 'Home', ip_address)

            # Fetch devices associated with the logged-in user
            devices = UserDevices.query.filter_by(user_id=user.id).all()

            return render_template('home.html', user=user, devices=devices)
    else:
        flash('You need to log in first.')
        return redirect(url_for('auth.login'))
    
@home_bp.route('/faq')
def faq():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        ip_address = get_public_ip()  # Use get_public_ip() to get the correct IP
        log_activity(user.username, 'FAQ', ip_address)
    return render_template('faq.html')

@home_bp.route('/od')
def od():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        ip_address = get_public_ip()  # Use get_public_ip() to get the correct IP
        log_activity(user.username, 'FAQ', ip_address)
    return render_template('od.html')




@home_bp.route('/scan_wifi', methods=['POST'])
def scan_wifi():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
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
        if user:
            ip_address = get_public_ip()  # Use get_public_ip() to get the correct IP
            log_activity(user.username, 'Scan Network', ip_address)
            devices = scan_smart_devices()
            return render_template('home.html', devices=devices)
    else:
        flash('You need to log in first.')
        return redirect(url_for('auth.login'))

@home_bp.route('/log_bluetooth_device', methods=['POST'])
def log_bluetooth_device_route():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            ip_address = get_public_ip()  # Use get_public_ip() to get the correct IP
            log_activity(user.username, 'Scan Bluetooth', ip_address)
        data = request.get_json()
        device_name = data.get('device_name')
        device_id = data.get('device_id')

        # Check if the device is already associated with the user
        existing_device = UserDevices.query.filter_by(user_id=user.id, device_id=device_id).first()
        if existing_device:
            return jsonify({'message': 'Device already associated with the user'}), 200

        # Add the device to the user's profile
        new_device = UserDevices(user_id=user.id, device_name=device_name, device_id=device_id)
        db.session.add(new_device)
        db.session.commit()

        return jsonify({'message': 'Bluetooth device added to user profile'}), 200
    return jsonify({'error': 'Unauthorized'}), 401

@home_bp.route('/log_bluetooth_scan', methods=['POST'])
def log_bluetooth_scan():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            ip_address = get_public_ip()  # Use get_public_ip() to get the correct IP
            log_activity(user.username, 'Performed Bluetooth Scan', ip_address)
            return jsonify({'message': 'Bluetooth scan logged successfully.'}), 200
    return jsonify({'error': 'Unauthorized'}), 401