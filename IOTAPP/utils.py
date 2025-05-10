import requests
from models import db, Activity, AccessLog

def getIP():#method to get ip for logging
    
    try:
        response = requests.get('https://api.ipify.org?format=json')
        ip = response.json().get('ip')
        return ip
    except Exception as e:
        print(f"Error getting public IP: {e}")
        return '0.0.0.0'#should there be an error it registers 0.0.0.0

def log_activity(username, action, ip_address):
    #activity logging
    activity = Activity(username=username, action=action, ip_address=ip_address)
    db.session.add(activity)
    db.session.commit()

def log_access_attempt(username, ip_address):
    #access attempt logging
    access_log = AccessLog(username=username, ip_address=ip_address)
    db.session.add(access_log)
    db.session.commit()

def log_page_access(username, page, ip_address):
    # page access logging
    activity = Activity(username=username, action=f"Visited {page} Page", ip_address=ip_address)
    db.session.add(activity)
    db.session.commit()
