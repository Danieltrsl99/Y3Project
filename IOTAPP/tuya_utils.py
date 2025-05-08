import time
import hmac
import hashlib
import requests
import logging
import json
from config import ACCESS_ID, ACCESS_KEY, API_BASE_URL, USER_UID

logging.basicConfig(level=logging.DEBUG)

class TuyaAPIError(Exception):
    """Custom exception for Tuya API errors."""
    pass

cached_token = {"token": None, "expire_time": 0}

def get_token():
    """Fetch or cache the Tuya API token."""
    global cached_token
    if cached_token["expire_time"] > time.time():
        return cached_token["token"]

    t = str(int(time.time() * 1000))
    method = "GET"
    sign_url = "/v1.0/token?grant_type=1"
    content_hash = hashlib.sha256("".encode("utf-8")).hexdigest()
    string_to_sign = f"{method}\n{content_hash}\n\n{sign_url}"

    sign_str = ACCESS_ID + t + string_to_sign
    sign = hmac.new(
        ACCESS_KEY.encode("utf-8"),
        sign_str.encode("utf-8"),
        hashlib.sha256
    ).hexdigest().upper()

    headers = {
        "t": t,
        "sign_method": "HMAC-SHA256",
        "client_id": ACCESS_ID,
        "sign": sign,
    }

    response = requests.get(f"{API_BASE_URL}/v1.0/token?grant_type=1", headers=headers)

    if response.status_code != 200:
        raise TuyaAPIError(f"Failed to get token: {response.text}")

    data = response.json()
    result = data.get("result", {})
    cached_token["token"] = result.get("access_token")
    cached_token["expire_time"] = time.time() + result.get("expire_time", 0) - 60
    return cached_token["token"]

def send_command(device_id, commands):
    """Send a command to a Tuya device."""
    token = get_token()
    t = str(int(time.time() * 1000))
    url_path = f"/v1.0/devices/{device_id}/commands"
    content_hash = hashlib.sha256(json.dumps({"commands": commands}).encode("utf-8")).hexdigest()
    string_to_sign = f"POST\n{content_hash}\n\n{url_path}"

    sign_str = ACCESS_ID + token + t + string_to_sign
    sign = hmac.new(
        ACCESS_KEY.encode("utf-8"),
        sign_str.encode("utf-8"),
        hashlib.sha256
    ).hexdigest().upper()

    headers = {
        "client_id": ACCESS_ID,
        "access_token": token,
        "sign": sign,
        "t": t,
        "sign_method": "HMAC-SHA256",
    }

    url = f"{API_BASE_URL}{url_path}"
    response = requests.post(url, headers=headers, json={"commands": commands})

    if response.status_code != 200:
        raise TuyaAPIError(f"Failed to send command: {response.text}")

    return response.json()

def turn_on(device_id):
    """Turn on the device."""
    return send_command(device_id, [{"code": "switch_led", "value": True}])

def turn_off(device_id):
    """Turn off the device."""
    return send_command(device_id, [{"code": "switch_led", "value": False}])

def set_brightness(device_id, brightness):
    """Set the brightness of the device."""
    return send_command(device_id, [{"code": "bright_value_v2", "value": brightness}])

def set_color(device_id, red, green, blue):
    """Set the color of the device."""

    # Convert RGB to HSV format to work with most Tuya app 
    r, g, b = red / 255.0, green / 255.0, blue / 255.0
    max_c = max(r, g, b)
    min_c = min(r, g, b)
    delta = max_c - min_c

    if delta == 0:
        h = 0
    elif max_c == r:
        h = (60 * ((g - b) / delta) + 360) % 360
    elif max_c == g:
        h = (60 * ((b - r) / delta) + 120) % 360
    elif max_c == b:
        h = (60 * ((r - g) / delta) + 240) % 360

    s = 0 if max_c == 0 else (delta / max_c) * 1000
    v = max_c * 1000

    hsv = {"h": int(h), "s": int(s), "v": int(v)}
    return send_command(device_id, [
        {"code": "work_mode", "value": "colour"},
        {"code": "colour_data_v2", "value": hsv}
    ])

def list_devices():
    """Fetch the list of devices from the Tuya API."""
    token = get_token()
    t = str(int(time.time() * 1000))
    url_path = "/v1.0/devices"
    content_hash = hashlib.sha256("".encode("utf-8")).hexdigest()
    string_to_sign = f"GET\n{content_hash}\n\n{url_path}"

    sign_str = ACCESS_ID + token + t + string_to_sign
    sign = hmac.new(
        ACCESS_KEY.encode("utf-8"),
        sign_str.encode("utf-8"),
        hashlib.sha256
    ).hexdigest().upper()

    headers = {
        "client_id": ACCESS_ID,
        "access_token": token,
        "sign": sign,
        "t": t,
        "sign_method": "HMAC-SHA256",
    }

    url = f"{API_BASE_URL}{url_path}"
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        raise TuyaAPIError(f"Failed to fetch devices: {response.text}")

    data = response.json()
    return data.get("result", {}).get("devices", [])