import os
import sqlite3
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
import requests
from scapy.all import ARP, Ether, srp
import pywifi
from pywifi import const

app = Flask(__name__)
app.secret_key = '123'

# Database configuration
db_path = os.path.join(os.path.dirname(__file__), 'database.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# User database model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(80), nullable=False, default='User')

# Create database if it does not exist
def init_db():
    if not os.path.exists(db_path):
        with app.app_context():
            db.create_all()
            with open(os.path.join(os.path.dirname(__file__), 'database.sql'), 'r') as f:
                sql_commands = f.read()
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                cursor.executescript(sql_commands)
                conn.commit()

# Initialize the database
init_db()

# Page loading for each web page
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
def home():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return render_template('home.html', user=user)
    else:
        flash('You need to log in first.')
        return redirect(url_for('login'))

# Admin page
@app.route('/Admin_page')
def Admin_page():
    if 'user_id' in session and session.get('user_role') == 'Admin':
        users = User.query.all()
        return render_template('Admin/Admin.html', users=users)
    else:
        return redirect(url_for('home'))

# Logout function
@app.route('/logout')
def logout():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        ip_address = get_public_ip()
        log_activity(user.username, 'Logout', ip_address)
        session.pop('user_id', None)
        session.pop('user_role', None)
    return redirect(url_for('index'))

# Register function
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('register.html')

# Login function
@app.route('/login', methods=['GET', 'POST'])
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
                return redirect(url_for('Admin_page'))
            else:
                return redirect(url_for('home'))
        else:
            log_access_attempt(username, ip_address)
            return redirect(url_for('login'))
    return render_template('login.html')

# Function to retrieve user's public IP address
def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json')
        ip = response.json().get('ip')
        return ip
    except Exception as e:
        print(f"Error fetching public IP: {e}")
        return 'Unknown'

# View activity logs
@app.route('/view_activity')
def view_activity():
    if 'user_id' in session and session.get('user_role') == 'Admin':
        activities = Activity.query.all()
        columns = ['ID', 'Username', 'Action', 'Timestamp', 'IP Address']
        data = [[activity.id, activity.username, activity.action, activity.timestamp, activity.ip_address] for activity in activities]
        return render_template('admin/admin.html', data=data, columns=columns)
    else:
        flash('You do not have permission to access this page.')
        return redirect(url_for('home'))

# View access logs
@app.route('/view_access_log')
def view_access_log():
    if 'user_id' in session and session.get('user_role') == 'Admin':
        access_logs = AccessLog.query.all()
        columns = ['ID', 'Username', 'Timestamp', 'IP Address']
        data = [[log.id, log.username, log.timestamp, log.ip_address] for log in access_logs]
        return render_template('admin/admin.html', data=data, columns=columns)
    else:
        flash('You do not have permission to access this page.')
        return redirect(url_for('home'))

# View users
@app.route('/view_users')
def view_users():
    if 'user_id' in session and session.get('user_role') == 'Admin':
        users = User.query.all()
        columns = ['ID', 'Username', 'Email', 'Role']
        data = [[user.id, user.username, user.email, user.role] for user in users]
        return render_template('admin/admin.html', data=data, columns=columns)
    else:
        flash('You do not have permission to access this page.')
        return redirect(url_for('home'))

# Functionality to monitor logins, logouts, failed logins, and general activity
class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(80), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(120))

class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(120))

def log_activity(username, action, ip_address):
    activity = Activity(username=username, action=action, ip_address=ip_address)
    db.session.add(activity)
    db.session.commit()

def log_access_attempt(username, ip_address):
    access_log = AccessLog(username=username, ip_address=ip_address)
    db.session.add(access_log)
    db.session.commit()

# Scan for Wi-Fi networks
@app.route('/scan_wifi', methods=['POST'])
def scan_wifi():
    if 'user_id' in session:
        wifi = pywifi.PyWiFi()
        interfaces = wifi.interfaces()
        if not interfaces:
            flash('No Wi-Fi interfaces found.')
            return redirect(url_for('home'))
        
        iface = interfaces[0]
        iface.scan()
        scan_results = iface.scan_results()
        networks = []
        for network in scan_results:
            networks.append({
                'ssid': network.ssid,
                'bssid': network.bssid,
                'signal': network.signal,
                'frequency': network.freq
            })
        return render_template('home.html', networks=networks)
    else:
        flash('You need to log in first.')
        return redirect(url_for('login'))

@app.route('/scan_network', methods=['POST'])
def scan_network():
    if 'user_id' in session:
        target_ip = "109.77.18.0/24"  # Change this to your network's IP range
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        result = srp(packet, timeout=3, verbose=0)[0]

        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})

        return render_template('home.html', devices=devices)
    else:
        flash('You need to log in first.')
        return redirect(url_for('login'))

# Make session available in templates
@app.context_processor
def inject_user():
    return dict(session=session)

if __name__ == '__main__':
    app.run(debug=True, port=80)