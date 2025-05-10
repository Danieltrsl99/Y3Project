from flask import Blueprint, render_template, session, redirect, url_for, request, jsonify
from utils import log_activity, getIP
from models import User, db, Activity, AccessLog

homeblue = Blueprint('home', __name__)

@homeblue.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        ip_address = getIP()  
        log_activity(user.username, 'Index', ip_address)
    return render_template('index.html')

@homeblue.route('/home')#inxex page 
def home():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            ip_address = getIP()  
            log_activity(user.username, 'Home', ip_address)
            return render_template('index.html', user=user)  
    else:
        return redirect(url_for('auth.login'))

@homeblue.route('/passcheck')#password checker page
def passcheck():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        ip_address = getIP()  
        log_activity(user.username, 'PassCheck', ip_address)
    return render_template('passcheck.html')

@homeblue.route('/faq')#faq page 
def faq():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        ip_address = getIP()  
        log_activity(user.username, 'FAQ', ip_address)
    return render_template('faq.html')

