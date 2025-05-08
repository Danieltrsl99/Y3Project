from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash
from models import User, db
from routes.tuya_routes import list_devices  
from routes.tuya_routes import control_device  
from tuya_utils import turn_on, turn_off, set_brightness, set_color  
from sqlalchemy.sql import text  

profile_bp = Blueprint('profile', __name__)
dash_bp = Blueprint('dashboard', __name__)

@profile_bp.route('/profile')
def profile():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:  
         return render_template('profile.html', user=user)
        else:
            session.clear()
            flash('Session is invalid. Please log in again.')
            return redirect(url_for('auth.login'))
    else:
        flash('You need to log in first.')
        return redirect(url_for('auth.login'))

@dash_bp.route('/dashboard', methods=['GET'])
def dashboard():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            try:
                # gets devices from the Tuya API
                tuya_devices = list_devices()
                tuya_device_ids = {device['id'] for device in tuya_devices}

                # finds devices assigned to the user from the database

                page = request.args.get('page', 1, type=int)

                per_page = 4  # Maximum 4 devices per page

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

                return render_template('dashboard.html', user=user, devices=devices, pagination=pagination)
            except Exception as e:
                flash(f"Error fetching devices: {str(e)}")
                return render_template('dashboard.html', user=user, devices=[], pagination={})
        else:
            session.clear()
            flash('Session is invalid. Please log in again.')
            return redirect(url_for('auth.login'))
    else:
        flash('You need to log in first.')
        return redirect(url_for('auth.login'))



@dash_bp.route('/dashboard/control/<device_id>', methods=['POST'])
def control_device_route(device_id):
    if 'user_id' in session:
        action = request.form.get('action')
        try:
            # functions for color input
            color_hex = request.form.get('color', '#ffffff')
            red, green, blue = hex_to_rgb(color_hex)
            brightness = int(request.form.get('brightness', 100) or 100)

            if action == 'set':
                # set color and brightness
                set_color(device_id, red, green, blue)
                set_brightness(device_id, brightness)
                
                flash(f"Color and brightness set for device {device_id}.")
            elif action == 'change_color':
                
                set_color(device_id, red, green, blue)
                flash(f"Color changed for device {device_id}.")
            elif action == 'turn_on':
                
                turn_on(device_id)
                
                flash(f"Device {device_id} turned on.")
            elif action == 'turn_off':
                turn_off(device_id)
                
                flash(f"Device {device_id} turned off.")
            elif action == 'set_brightness':
                
                set_brightness(device_id, brightness)
                flash(f"Brightness set for device {device_id}.")
        except Exception as e:
            flash(f"Error controlling device {device_id}: {str(e)}")

   
        return redirect(url_for('dashboard.dashboard'))
    else:
        flash('You need to log in first.')
        return redirect(url_for('auth.login'))

def hex_to_rgb(hex_color):
    """Convert hex color to RGB tuple."""
    hex_color = hex_color.lstrip('#')
    return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

@profile_bp.route('/profile/update_username', methods=['POST'])
def update_username():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        new_username = request.form['username']
        if User.query.filter_by(username=new_username).first():
            flash('Username already exists.')
        else:
            user.username = new_username
            db.session.commit()
            flash('Username updated successfully.')
        return redirect(url_for('profile.profile'))
    else:
        flash('You need to log in first.')
        return redirect(url_for('auth.login'))

@profile_bp.route('/profile/update_email', methods=['POST'])
def update_email():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        new_email = request.form['email']
        if User.query.filter_by(email=new_email).first():
            flash('Email already exists.')
        else:
            user.email = new_email
            db.session.commit()
            flash('Email updated successfully.')
        return redirect(url_for('profile.profile'))
    else:
        flash('You need to log in first.')
        return redirect(url_for('auth.login'))

@profile_bp.route('/profile/reset_password', methods=['POST'])
def reset_password():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        new_password = request.form['password']
        hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')  # Hash the new password for users
        user.password = hashed_password
        db.session.commit()
        flash('Password reset successfully.')
        return redirect(url_for('profile.profile'))
    else:
        flash('You need to log in first.')
        return redirect(url_for('auth.login'))