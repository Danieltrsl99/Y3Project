import requests
from scapy.all import ARP, Ether, srp
from pywifi import PyWiFi
from models import db, Activity, AccessLog

def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json')
        ip = response.json().get('ip')
        return ip
    except Exception as e:
        print(f"Error fetching public IP: {e}")
        return 'Unknown'

def log_activity(username, action, ip_address):
    activity = Activity(username=username, action=action, ip_address=ip_address)
    db.session.add(activity)
    db.session.commit()

def log_access_attempt(username, ip_address):
    access_log = AccessLog(username=username, ip_address=ip_address)
    db.session.add(access_log)
    db.session.commit()

def log_page_access(username, page, ip_address):
    """
    Logs a user's page access activity into the Activity table.
    """
    activity = Activity(username=username, action=f"Visited {page} Page", ip_address=ip_address)
    db.session.add(activity)
    db.session.commit()
