from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from models import User, db
from routes.tuya_routes import devicelist  
from tuya_utils import turn_on, turn_off, brightness, color  
from sqlalchemy.sql import text  
from utils import log_activity, getIP

profblue = Blueprint('profile', __name__)
dashblue = Blueprint('dashboard', __name__)

@profblue.route('/profile')#profile pagge is loaded if users is logged in 
def profile():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:  
            ip_address = getIP()  
            log_activity(user.username, 'Profile', ip_address)    # any time you see this it logs what user done 
        return render_template('profile.html', user=user)
   
    else:
        return redirect(url_for('auth.login'))

@dashblue.route('/dashboard', methods=['GET'])#dashboard to control devices
def dashboard():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            try:
                
                tuya_devices = devicelist()#lists all devices in tuya 
                tuya_device_ids = {device['id'] for device in tuya_devices}

                

                page = request.args.get('page', 1, type=int)

                per_page = 4  

                user_devices_query = db.session.execute(
                    text("""
                        SELECT d.id, d.tuya_device_id, d.name
                        FROM devices d
                        WHERE d.assigned_user_id = :user_id
                    """),
                    {"user_id": user.id}
                ).fetchall()

                user_devices = [
                    device for device in user_devices_query if device.tuya_device_id in tuya_device_ids
                ]

                total_devices = len(user_devices)
                start = (page - 1) * per_page
                end = start + per_page
                paginated_devices = user_devices[start:end]

        
                devices = [
                    {
                        "id": device.tuya_device_id,
                        "name": device.name,
                        "current_color": "#ffffff",  
                        "current_brightness": 100,  
                    }
                    for device in paginated_devices
                ]

                pagination = {
                    "page": page,
                    "per_page": per_page,
                    "total": total_devices,
                    "has_next": end < total_devices,
                    "has_prev": start > 0,
                    "next_num": page + 1,
                    "prev_num": page - 1,
                }
                ip_address = getIP()  
                log_activity(user.username, 'Dashboard', ip_address)
                return render_template('dashboard.html', user=user, devices=devices, pagination=pagination)
            except Exception as e:
                return render_template('dashboard.html', user=user, devices=[], pagination={})
        else:
            session.clear()           
            return redirect(url_for('auth.login'))
    else:      
        return redirect(url_for('auth.login'))



@dashblue.route('/dashboard/control/<device_id>', methods=['POST']) #functionality to control devices
def control_device_route(device_id):
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            
            device = db.session.execute(
                text("SELECT * FROM devices WHERE tuya_device_id = :device_id AND assigned_user_id = :user_id"),
                {"device_id": device_id, "user_id": user.id}
            ).fetchone()

            if not device:
                return redirect(url_for('dashboard.dashboard'))

            
            entered_password = request.form.get('password') #verifies for password 
            if not entered_password or not check_password_hash(device.password, entered_password):
                return redirect(url_for('dashboard.dashboard'))

            
            action = request.form.get('action')
            try:
                if action == 'turn_on':#turn on/off briightnes and colour selection
                    turn_on(device_id)
                elif action == 'turn_off':
                    turn_off(device_id)
                elif action == 'brightness':
                    brightness_value = int(request.form.get('brightness', 100))
                    brightness(device_id, brightness_value)
                elif action == 'color':
                    color_hex = request.form.get('color', '#ffffff')
                    color(device_id, color_hex)
            except Exception as e:
                return redirect(url_for('dashboard.dashboard'))
    else:
        return redirect(url_for('auth.login'))

def hex_to_rgb(hex_color):# important to convert rbg to hex, some devices only support hex

    hex_color = hex_color.lstrip('#')
    return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

@profblue.route('/profile/update_username', methods=['POST']) #update username
def update_username():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        new_username = request.form['username']
        if User.query.filter_by(username=new_username).first():
            flash('Username Taken.')
        else:
            user.username = new_username
            db.session.commit()
            ip_address = getIP()  
            log_activity(user.username, 'Email Reset', ip_address) 
        return redirect(url_for('profile.profile'))
    else:
        return redirect(url_for('auth.login'))

@profblue.route('/profile/update_email', methods=['POST'])#update email 
def update_email():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        new_email = request.form['email']
        if User.query.filter_by(email=new_email).first():
            flash('Email Taken')
        else:
            user.email = new_email
            db.session.commit()
            ip_address = getIP()  
            log_activity(user.username, 'Email Reset', ip_address) 
        return redirect(url_for('profile.profile'))
    else:
        return redirect(url_for('auth.login'))

@profblue.route('/profile/reset_password', methods=['POST'])#password resrt
def reset_password():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        new_password = request.form['password']
        hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')  
        user.password = hashed_password
        db.session.commit()
        ip_address = getIP()  
        log_activity(user.username, 'Password Reset', ip_address) 
        return redirect(url_for('profile.profile'))
    else:
        return redirect(url_for('auth.login'))