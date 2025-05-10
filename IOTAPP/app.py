from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
from models import init_db
from routes.auth_routes import authblue
from routes.admin_routes import adminblue
from routes.home_routes import homeblue
from routes.profile_routes import profblue, dashblue
from routes.tuya_routes import tuyablue


app = Flask(__name__)
app.secret_key = '123'


init_db(app)

#blueprints from routes 
app.register_blueprint(authblue, url_prefix='/auth')
app.register_blueprint(adminblue, url_prefix='/admin')
app.register_blueprint(homeblue)
app.register_blueprint(profblue, url_prefix='/profile')
app.register_blueprint(tuyablue, url_prefix='/tuya')
app.register_blueprint(dashblue, url_prefix='/dashboard')




@app.context_processor
def inject_user():
    from flask import session
    return dict(session=session)

if __name__ == '__main__':
    app.run(port=80)