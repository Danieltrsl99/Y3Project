from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
from models import init_db
from routes.auth_routes import auth_bp
from routes.admin_routes import admin_bp
from routes.home_routes import home_bp
from routes.profile_routes import profile_bp, dash_bp
from routes.tuya_routes import tuya_bp


app = Flask(__name__)
app.secret_key = '123'


init_db(app)

#blueprints from routes
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(admin_bp, url_prefix='/admin')
app.register_blueprint(home_bp)
app.register_blueprint(profile_bp, url_prefix='/profile')
app.register_blueprint(tuya_bp, url_prefix='/tuya')
app.register_blueprint(dash_bp, url_prefix='/dashboard')




@app.context_processor
def inject_user():
    from flask import session
    return dict(session=session)

if __name__ == '__main__':
    app.run(debug=True, port=80)