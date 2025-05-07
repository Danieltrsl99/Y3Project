from flask import Blueprint, render_template, session, redirect, url_for, flash, request
from models import User, Activity, AccessLog, db  # Import db here
from utils import log_activity, get_public_ip
from tuya_utils import list_devices  # Import the function to fetch devices
from sqlalchemy.sql import text  # Import text for raw SQL queries
from routes.tuya_routes import list_devices 

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/admin_page')
def admin_page():
    if 'user_id' in session and session.get('user_role') == 'Admin':
        user = User.query.get(session['user_id'])
        ip_address = get_public_ip()  # Use get_public_ip() to get the correct IP
        log_activity(user.username, 'Admin Page', ip_address)
        users = User.query.all()
        return render_template('admin/admin.html', users=users)
    else:
        flash('You do not have permission to access this page.')
        return redirect(url_for('home.home'))

@admin_bp.route('/view_activity')
def view_activity():
    if 'user_id' in session and session.get('user_role') == 'Admin':
        user = User.query.get(session['user_id'])  # Retrieve the user from the session
        ip_address = get_public_ip()  # Use get_public_ip() to get the correct IP
        log_activity(user.username, 'View Activity', ip_address)  # Log the activity

        # Pagination logic
        page = request.args.get('page', 1, type=int)  # Get the current page number from query params
        per_page = 25  # Number of entries per page
        activities = Activity.query.paginate(page=page, per_page=per_page)

        columns = ['ID', 'Username', 'Action', 'Timestamp', 'IP Address']
        data = [[activity.id, activity.username, activity.action, activity.timestamp, activity.ip_address] for activity in activities.items]

        return render_template(
            'admin/admin.html',
            data=data,
            columns=columns,
            pagination=activities
        )
    else:
        flash('You do not have permission to access this page.')
        return redirect(url_for('home.home'))

@admin_bp.route('/view_access_log')
def view_access_log():
    if 'user_id' in session and session.get('user_role') == 'Admin':
        user = User.query.get(session['user_id'])  # Retrieve the user from the session
        ip_address = get_public_ip()  # Use get_public_ip() to get the correct IP
        log_activity(user.username, 'View Access', ip_address)

        # Pagination logic
        page = request.args.get('page', 1, type=int)
        per_page = 25
        access_logs = AccessLog.query.paginate(page=page, per_page=per_page)

        columns = ['ID', 'Username', 'Timestamp', 'IP Address']
        data = [[log.id, log.username, log.timestamp, log.ip_address] for log in access_logs.items]

        return render_template(
            'admin/admin.html',
            data=data,
            columns=columns,
            pagination=access_logs
        )
    else:
        flash('You do not have permission to access this page.')
        return redirect(url_for('home.home'))

@admin_bp.route('/view_users')
def view_users():
    if 'user_id' in session and session.get('user_role') == 'Admin':
        user = User.query.get(session['user_id'])  # Retrieve the user from the session
        ip_address = get_public_ip()  # Use get_public_ip() to get the correct IP
        log_activity(user.username, 'View Users', ip_address)

        # Pagination logic
        page = request.args.get('page', 1, type=int)
        per_page = 25
        users = User.query.paginate(page=page, per_page=per_page)

        columns = ['ID', 'Username', 'Email', 'Role']
        data = [[user.id, user.username, user.email, user.role] for user in users.items]

        return render_template(
            'admin/admin.html',
            data=data,
            columns=columns,
            pagination=users
        )
    else:
        flash('You do not have permission to access this page.')
        return redirect(url_for('home.home'))
    
@admin_bp.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user_id' in session and session.get('user_role') == 'Admin':
        user = User.query.get_or_404(user_id)
        if request.method == 'POST':
            user.username = request.form['username']
            user.email = request.form['email']
            user.role = request.form['role'] 
            db.session.commit()
            flash('User updated successfully.')
            return redirect(url_for('admin.view_users'))  
        return render_template('admin/edit_users.html', user=user)
    else:
        flash('You do not have permission to access this page.')
        return redirect(url_for('home.home'))

@admin_bp.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' in session and session.get('user_role') == 'Admin':
        user_to_delete = User.query.get_or_404(user_id)
        db.session.delete(user_to_delete)
        db.session.commit()
        flash('User deleted successfully.')
        return redirect(url_for('admin.view_users'))
    else:
        flash('You do not have permission to access this page.')
        return redirect(url_for('home.home'))

@admin_bp.route('/assign_device', methods=['GET'])
def assign_device():
    if 'user_id' in session and session.get('user_role') == 'Admin':
        user = User.query.get(session['user_id'])  # Retrieve the user from the session
        ip_address = get_public_ip()  # Use get_public_ip() to get the correct IP
        log_activity(user.username, 'View Assign Device', ip_address)  # Log the activity

        # Fetch devices from Tuya API
        try:
            devices = list_devices()  # Fetch devices from Tuya API
            # Add default status for devices if not provided
            for device in devices:
                device['status'] = device.get('status', 'Unknown')  # Add a default status
        except Exception as e:
            flash(f"Error fetching devices: {str(e)}")
            devices = []

        # Fetch all users to allow assigning devices
        users = User.query.all()

        return render_template('admin/assign_device.html', devices=devices, users=users)
    else:
        flash('You do not have permission to access this page.')
        return redirect(url_for('home.home'))


@admin_bp.route('/view_device')
def view_device():
    if 'user_id' in session and session.get('user_role') == 'Admin':
        user = User.query.get(session['user_id'])  # Retrieve the user from the session
        ip_address = get_public_ip()  # Use get_public_ip() to get the correct IP
        log_activity(user.username, 'View Devices', ip_address)  # Log the activity

        # Pagination logic
        page = request.args.get('page', 1, type=int)
        per_page = 25
        devices = db.session.execute(
            text("""
                SELECT d.id, d.tuya_device_id, d.name, u.username
                FROM devices d
                LEFT JOIN user u ON d.assigned_user_id = u.id
            """)
        ).fetchall()

        # Paginate manually since raw SQL doesn't support Flask-SQLAlchemy's paginate
        total_devices = len(devices)
        start = (page - 1) * per_page
        end = start + per_page
        paginated_devices = devices[start:end]

        columns = ['Device ID', 'Device Name', 'Device Tuya ID', 'Assigned Username']
        data = [[device.id, device.name, device.tuya_device_id, device.username or 'Unassigned'] for device in paginated_devices]

        return render_template(
            'admin/admin.html',
            data=data,
            columns=columns,
            pagination={
                'page': page,
                'per_page': per_page,
                'total': total_devices,
                'has_next': end < total_devices,
                'has_prev': start > 0,
                'next_num': page + 1,
                'prev_num': page - 1
            }
        )
    else:
        flash('You do not have permission to access this page.')
        return redirect(url_for('home.home'))

@admin_bp.route('/remove_device/<int:device_id>', methods=['POST'])
def remove_device(device_id):
    if 'user_id' in session and session.get('user_role') == 'Admin':
        # Fetch the device from the database using the correct model
        device_to_delete = db.session.execute(
            text("SELECT * FROM devices WHERE id = :device_id"),
            {"device_id": device_id}
        ).fetchone()

        if device_to_delete:
            db.session.execute(
                text("DELETE FROM devices WHERE id = :device_id"),
                {"device_id": device_id}
            )
            db.session.commit()
            flash('Device deleted successfully.')
        else:
            flash('Device not found.')

        return redirect(url_for('admin.view_device'))
    else:
        flash('You do not have permission to perform this action.')
        return redirect(url_for('home.home'))

@admin_bp.route('/assign_device_from_tuya', methods=['GET', 'POST'])
def assign_device_from_tuya():
    if 'user_id' in session and session.get('user_role') == 'Admin':
        try:
            # Fetch devices from Tuya API
            devices = list_devices()  # Fetch all devices from Tuya API

            # Fetch all assigned device IDs from the database
            assigned_devices = db.session.execute(
                text("SELECT tuya_device_id FROM devices")
            ).fetchall()
            assigned_device_ids = {device.tuya_device_id for device in assigned_devices}

            # Filter out already assigned devices
            available_devices = [
                device for device in devices if device['id'] not in assigned_device_ids
            ]

            # Fetch all users from the database
            users = User.query.all()

            if request.method == 'POST':
                # Get form data
                device_id = request.form.get('device_id')
                user_id = request.form.get('user_id')

                # Get the selected device name
                device_name = next((device['name'] for device in devices if device['id'] == device_id), None)

                if not device_name:
                    flash('Invalid device selected.')
                    return redirect(url_for('admin.assign_device_from_tuya'))

                # Assign the device to the user
                db.session.execute(
                    text("INSERT INTO devices (tuya_device_id, name, assigned_user_id) VALUES (:device_id, :device_name, :user_id)"),
                    {"device_id": device_id, "device_name": device_name, "user_id": user_id}
                )
                db.session.commit()
                flash(f'Device "{device_name}" assigned successfully.')

                return redirect(url_for('admin.assign_device_from_tuya'))

            return render_template('admin/assign_device_from_tuya.html', devices=available_devices, users=users)
        except Exception as e:
            flash(f"Error fetching devices or users: {str(e)}")
            return redirect(url_for('admin.admin_page'))
    else:
        flash('You do not have permission to access this page.')
        return redirect(url_for('home.home'))