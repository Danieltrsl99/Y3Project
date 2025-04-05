from flask import Blueprint, render_template, session, redirect, url_for, flash, request
from models import User, Activity, AccessLog, db  # Import db here
from utils import log_activity, get_public_ip

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
        activities = Activity.query.all()
        columns = ['ID', 'Username', 'Action', 'Timestamp', 'IP Address']
        data = [[activity.id, activity.username, activity.action, activity.timestamp, activity.ip_address] for activity in activities]
        return render_template('admin/admin.html', data=data, columns=columns)
    else:
        flash('You do not have permission to access this page.')
        return redirect(url_for('home.home'))

@admin_bp.route('/view_access_log')
def view_access_log():
    if 'user_id' in session and session.get('user_role') == 'Admin':
        user = User.query.get(session['user_id'])  # Retrieve the user from the session
        ip_address = get_public_ip()  # Use get_public_ip() to get the correct IP
        log_activity(user.username, 'View Access', ip_address)
        access_logs = AccessLog.query.all()
        columns = ['ID', 'Username', 'Timestamp', 'IP Address']
        data = [[log.id, log.username, log.timestamp, log.ip_address] for log in access_logs]
        return render_template('admin/admin.html', data=data, columns=columns)
    else:
        flash('You do not have permission to access this page.')
        return redirect(url_for('home.home'))

@admin_bp.route('/view_users')
def view_users():
    if 'user_id' in session and session.get('user_role') == 'Admin':
        user = User.query.get(session['user_id'])  # Retrieve the user from the session
        ip_address = get_public_ip()  # Use get_public_ip() to get the correct IP
        log_activity(user.username, 'View Users', ip_address)
        users = User.query.all()
        columns = ['ID', 'Username', 'Email', 'Role']
        data = [[user.id, user.username, user.email, user.role] for user in users]
        return render_template('admin/admin.html', data=data, columns=columns)
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