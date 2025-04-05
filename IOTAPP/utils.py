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

def log_bluetooth_device(username, device_name, device_id, ip_address):
    """
    Logs a Bluetooth device detected by the user.
    """
    activity = Activity(username=username, action=f"Detected Bluetooth Device: {device_name} (ID: {device_id})", ip_address=ip_address)
    db.session.add(activity)
    db.session.commit()

def scan_wifi_networks():
    wifi = PyWiFi()
    interfaces = wifi.interfaces()
    if not interfaces:
        return []
    iface = interfaces[0]
    iface.scan()
    scan_results = iface.scan_results()
    networks = []
    for network in scan_results:
        networks.append({
            'ssid': network.ssid,
            'bssid': network.bssid,
            'signal': network.signal,
            'frequency': network.freq
        })
    return networks

def scan_smart_devices():
    target_ip = get_public_ip()  # Change this to your network's IP range
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]
    devices = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in result]
    return devices