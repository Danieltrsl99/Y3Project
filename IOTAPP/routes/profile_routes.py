from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash
from models import User, UserDevices, db

profile_bp = Blueprint('profile', __name__)

@profile_bp.route('/profile')
def profile():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            # Fetch devices associated with the logged-in user
            devices = UserDevices.query.filter_by(user_id=user.id).all()
            return render_template('profile.html', user=user, devices=devices)
    flash('You need to log in first.')
    return redirect(url_for('auth.login'))

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
        hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')  # Hash the new password
        user.password = hashed_password
        db.session.commit()
        flash('Password reset successfully.')
        return redirect(url_for('profile.profile'))
    else:
        flash('You need to log in first.')
        return redirect(url_for('auth.login'))