from flask import Blueprint, render_template, session, redirect, url_for, request
from models import db, User, Activity, AccessLog
from utils import log_activity, getIP
from tuya_utils import devicelist
from sqlalchemy.sql import text
from werkzeug.security import generate_password_hash, check_password_hash

adminblue = Blueprint('admin', __name__)

@adminblue.route('/admin_page')
def admin_page():
    if 'user_id' in session and session.get('user_role') == 'Admin':
        user = User.query.get(session['user_id'])
        ip_address = getIP()
        log_activity(user.username, 'Admin Page', ip_address)
        users = User.query.all()
        return render_template('admin/admin.html', users=users)
    else:
        return redirect(url_for('home.home'))

@adminblue.route('/view_activity')#lets admin view activity accross the app
def view_activity():
    if 'user_id' in session and session.get('user_role') == 'Admin':
        user = User.query.get(session['user_id'])
        ip_address = getIP()
        log_activity(user.username, 'View Activity', ip_address)

        page = request.args.get('page', 1, type=int)
        per_page = 25
        activities = Activity.query.paginate(page=page, per_page=per_page)

        columns = ['ID', 'Username', 'Action', 'Timestamp', 'IP Address']#records this data to logs
        data = [[activity.id, activity.username, activity.action, activity.timestamp, activity.ip_address] for activity in activities.items]

        return render_template(
            'admin/admin.html',
            data=data,
            columns=columns,
            pagination=activities
        )
    else:
        return redirect(url_for('home.home'))

@adminblue.route('/view_access_log') #lets admin view attempts to log in 
def view_access_log():
    if 'user_id' in session and session.get('user_role') == 'Admin':
        user = User.query.get(session['user_id'])
        ip_address = getIP()
        log_activity(user.username, 'View Access', ip_address)

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
        return redirect(url_for('home.home'))

@adminblue.route('/view_users')#lets admin view users 
def view_users():
    if 'user_id' in session and session.get('user_role') == 'Admin':
        user = User.query.get(session['user_id'])
        ip_address = getIP()
        log_activity(user.username, 'View Users', ip_address)

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
        return redirect(url_for('home.home'))

@adminblue.route('/edit_user/<int:user_id>', methods=['GET', 'POST']) #lets admin edit user details
def edit_user(user_id):
    if 'user_id' in session and session.get('user_role') == 'Admin':
        user = User.query.get_or_404(user_id)
        if request.method == 'POST':
            user.username = request.form['username']
            user.email = request.form['email']
            user.role = request.form['role']
            db.session.commit()
            return redirect(url_for('admin.view_users'))
        return render_template('admin/edit_users.html', user=user)
    else:
        return redirect(url_for('home.home'))

@adminblue.route('/delete_user/<int:user_id>', methods=['POST'])#lets admin delete user
def delete_user(user_id):
    if 'user_id' in session and session.get('user_role') == 'Admin':
        user_to_delete = User.query.get_or_404(user_id)
        db.session.delete(user_to_delete)
        db.session.commit()
        return redirect(url_for('admin.view_users'))
    else:
        return redirect(url_for('home.home'))

@adminblue.route('/assign_device', methods=['GET'])#lets admin assign devices to users
def assign_device():
    if 'user_id' in session and session.get('user_role') == 'Admin':
        user = User.query.get(session['user_id'])
        ip_address = getIP()
        log_activity(user.username, 'Assign Device', ip_address)

        try:
            devices = devicelist() 
            for device in devices:
                device['status'] = device.get('status', 'Unknown')
        except Exception:
            devices = []

        users = User.query.all()

        return render_template('admin/assign_device.html', devices=devices, users=users)
    else:
        return redirect(url_for('home.home'))

@adminblue.route('/view_device') #lets admin view devices
def view_device():
    if 'user_id' in session and session.get('user_role') == 'Admin':
        user = User.query.get(session['user_id'])
        ip_address = getIP()
        log_activity(user.username, 'View Devices', ip_address)

        page = request.args.get('page', 1, type=int)
        per_page = 25
        devices = db.session.execute(
            text("""
                SELECT d.id, d.tuya_device_id, d.name, u.username
                FROM devices d
                LEFT JOIN user u ON d.assigned_user_id = u.id
            """)
        ).fetchall()

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
        return redirect(url_for('home.home'))

@adminblue.route('/remove_device/<int:device_id>', methods=['POST'])#lets admin remove devices from users 
def remove_device(device_id):
    if 'user_id' in session and session.get('user_role') == 'Admin':
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

        return redirect(url_for('admin.view_device'))
    else:
        return redirect(url_for('home.home'))

@adminblue.route('/assign_device_from_tuya', methods=['GET', 'POST'])#lets admin assign devices
def assign_device_from_tuya():
    if 'user_id' in session and session.get('user_role') == 'Admin':
        try:
            devices = devicelist()

            assigned_devices = db.session.execute(
                text("SELECT tuya_device_id FROM devices")
            ).fetchall()
            assigned_device_ids = {device.tuya_device_id for device in assigned_devices}

            available_devices = [
                device for device in devices if device['id'] not in assigned_device_ids
            ]

            users = User.query.all()

            if request.method == 'POST':
                device_id = request.form.get('device_id')
                user_id = request.form.get('user_id')
                password = request.form.get('password')

                if not device_id or not user_id or not password:
                    return redirect(url_for('admin.assign_device_from_tuya'))

                device_name = next((device['name'] for device in devices if device['id'] == device_id), None)
                if not device_name:
                    return redirect(url_for('admin.assign_device_from_tuya'))

                hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

                try:
                    db.session.execute(
                        text("""
                            INSERT INTO devices (tuya_device_id, name, assigned_user_id, password)
                            VALUES (:device_id, :device_name, :user_id, :password)
                        """),
                        {"device_id": device_id, "device_name": device_name, "user_id": user_id, "password": hashed_password}
                    )
                    db.session.commit()
                except Exception:
                    return redirect(url_for('admin.assign_device_from_tuya'))

                return redirect(url_for('admin.assign_device_from_tuya'))

            return render_template('admin/assign_device_from_tuya.html', devices=available_devices, users=users)
        except Exception:
            return redirect(url_for('admin.admin_page'))
    else:
        return redirect(url_for('home.home'))