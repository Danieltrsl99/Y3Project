import time
import hmac
import hashlib
import requests
import logging
import json
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from config import accessid, accesskey, apiurl, userid
from werkzeug.security import check_password_hash
from sqlalchemy.sql import text
from utils import db

logging.basicConfig(level=logging.DEBUG)

tuyablue = Blueprint('tuya', __name__)

class TuyaAPIError(Exception):
    pass

cached_token = {"token": None, "expire_time": 0}

def get_token():# generates token to authenticate with tuya/ its then cached 
    global cached_token
    if cached_token["expire_time"] > time.time():
        return cached_token["token"]

    t = str(int(time.time() * 1000))
    method = "GET"
    sign_url = "/v1.0/token?grant_type=1" #token type
    content_hash = hashlib.sha256("".encode("utf-8")).hexdigest()
    string_to_sign = f"{method}\n{content_hash}\n\n{sign_url}"

    sign_str = accessid + t + string_to_sign
    sign = hmac.new(
        accesskey.encode("utf-8"),
        sign_str.encode("utf-8"),
        hashlib.sha256
    ).hexdigest().upper()

    headers = {#code example from tuya docuentaion
        "t": t,
        "sign_method": "HMAC-SHA256",
        "client_id": accessid,
        "sign": sign,       
    }

    response = requests.get(f"{apiurl}/v1.0/token?grant_type=1", headers=headers)

    if response.status_code != 200:
        raise TuyaAPIError(f"Failed to get token: {response.text}")

    data = response.json()

    if "result" not in data:
        raise TuyaAPIError(f"Unexpected token response format: {data}")

    result = data["result"]
    cached_token["token"] = result["access_token"]
    cached_token["expire_time"] = time.time() + result["expire_time"] - 60
    return cached_token["token"]

def devicelist(): #lists all devices from tuya 
    token = get_token()
    t = str(int(time.time() * 1000))

    method = "GET"
    url_path = f"/v1.0/users/{userid}/devices"
    content_hash = hashlib.sha256("".encode("utf-8")).hexdigest()
    string_to_sign = f"{method}\n{content_hash}\n\n{url_path}"

    sign_str = accessid + token + t + string_to_sign
    sign = hmac.new(
        accesskey.encode("utf-8"),
        sign_str.encode("utf-8"),
        hashlib.sha256
    ).hexdigest().upper()

    headers = {#code example from tuya docuentaion
        "client_id": accessid,
        "access_token": token,
        "sign": sign,
        "t": t,
        "sign_method": "HMAC-SHA256",
    }

    url = f"{apiurl}{url_path}"
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        raise TuyaAPIError(f"Failed to list devices: {response.text}")

    return response.json()["result"]

def get_device_specifications(device_id):#gets devices specs ti help with controls
    token = get_token()
    t = str(int(time.time() * 1000))

    method = "GET"
    url_path = f"/v1.0/devices/{device_id}/specifications"
    content_hash = hashlib.sha256("".encode("utf-8")).hexdigest()
    string_to_sign = f"{method}\n{content_hash}\n\n{url_path}"

    sign_str = accessid + token + t + string_to_sign
    sign = hmac.new(
        accesskey.encode("utf-8"),
        sign_str.encode("utf-8"),
        hashlib.sha256
    ).hexdigest().upper()

    headers = {
        "client_id": accessid,#code example from tuya docuentaion
        "access_token": token,
        "sign": sign,
        "t": t,
        "sign_method": "HMAC-SHA256",
    }

    url = f"{apiurl}{url_path}"
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        raise TuyaAPIError(f"Failed to get device specifications: {response.text}")

    return response.json()

def change_color(device_id, color):#color changing 
    token = get_token()
    t = str(int(time.time() * 1000))

    specs = get_device_specifications(device_id)
    functions = specs.get("result", {}).get("functions", [])
    dp_code = None

    if any(f["code"] == "colour_data_v2" for f in functions):
        dp_code = "colour_data_v2"

        r, g, b = color                             #needed caluclation for controls of color
        r, g, b = r / 255.0, g / 255.0, b / 255.0
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

        if v > 900: #max saturation 
            s = max(s, 500)

        value = {
            "h": int(h),
            "s": int(s),
            "v": int(v),
        }
    else:
        raise TuyaAPIError("Device does not support colour_data_v2 for color changing.")

    commands = [
        {
            "code": "work_mode",#mode compatible with most bulbs
            "value": "colour",
        },
        {
            "code": dp_code,
            "value": value,
        },
    ]

    method = "POST"
    url_path = f"/v1.0/devices/{device_id}/commands"
    content = {"commands": commands}
    content_hash = hashlib.sha256(json.dumps(content).encode("utf-8")).hexdigest()
    string_to_sign = f"{method}\n{content_hash}\n\n{url_path}"

    sign_str = accessid + token + t + string_to_sign
    sign = hmac.new(
        accesskey.encode("utf-8"),
        sign_str.encode("utf-8"),
        hashlib.sha256
    ).hexdigest().upper()

    headers = {
        "client_id": accessid,#code example from tuya docuentaion
        "access_token": token,
        "sign": sign,
        "t": t,
        "sign_method": "HMAC-SHA256",
    }

    url = f"{apiurl}{url_path}"
    response = requests.post(url, headers=headers, json=content)
    if response.status_code != 200:
        raise TuyaAPIError(f"Failed to change color: {response.text}")
    return response.json()

def change_power_state(device_id, state):#turn off/on
    token = get_token()
    t = str(int(time.time() * 1000))
    url_path = f"/v1.0/devices/{device_id}/commands"
    content = {
        "commands": [
            {
                "code": "switch_led", #turnign of method 
                "value": state,
            }
        ]
    }

    return send_tuya_command(url_path, content, token, t)

def change_brightness_level(device_id, brightness):#brightness
    token = get_token()
    t = str(int(time.time() * 1000))

    commands = [
        {
            "code": "bright_value_v2",  
            "value": int(brightness),  
        }
    ]

    method = "POST"
    url_path = f"/v1.0/devices/{device_id}/commands"
    content = {"commands": commands}
  
    content_hash = hashlib.sha256(json.dumps(content).encode("utf-8")).hexdigest()
    string_to_sign = f"{method}\n{content_hash}\n\n{url_path}"
    sign_str = accessid + token + t + string_to_sign
    sign = hmac.new(
        accesskey.encode("utf-8"),
        sign_str.encode("utf-8"),
        hashlib.sha256
    ).hexdigest().upper()

    headers = {
        "client_id": accessid,#code example from tuya docuentaion
        "access_token": token,
        "sign": sign,
        "t": t,
        "sign_method": "HMAC-SHA256",
    }

    url = f"{apiurl}{url_path}"
   
    response = requests.post(url, headers=headers, json=content)
    if response.status_code != 200:
        raise TuyaAPIError(f"Failed to change brightness: {response.text}")
    return response.json()

def send_tuya_command(url_path, content, token, t):
    content_hash = hashlib.sha256(json.dumps(content).encode("utf-8")).hexdigest()
    string_to_sign = f"POST\n{content_hash}\n\n{url_path}"
    sign_str = accessid + token + t + string_to_sign
    sign = hmac.new(
        accesskey.encode("utf-8"),
        sign_str.encode("utf-8"),
        hashlib.sha256
    ).hexdigest().upper()

    headers = {
        "client_id": accessid,#code example from tuya docuentaion
        "access_token": token,
        "sign": sign,
        "t": t,
        "sign_method": "HMAC-SHA256",
    }

    url = f"{apiurl}{url_path}"
    response = requests.post(url, headers=headers, json=content)
    if response.status_code != 200:
        raise TuyaAPIError(f"Failed to send command: {response.text}")
    return response.json()

def control_device(device_id, command, params):#sends data to tuya 
    token = get_token()
    t = str(int(time.time() * 1000))

    method = "POST"
    url_path = f"/v1.0/devices/{device_id}/commands"
    content_hash = hashlib.sha256("".encode("utf-8")).hexdigest()  
    string_to_sign = f"{method}\n{content_hash}\n\n{url_path}"

    sign_str = accessid + token + t + string_to_sign
    sign = hmac.new(
        accesskey.encode("utf-8"),
        sign_str.encode("utf-8"),
        hashlib.sha256
    ).hexdigest().upper()

    headers = {
        "client_id": accessid,#code example from tuya docuentaion
        "access_token": token,
        "sign": sign,
        "t": t,
        "sign_method": "HMAC-SHA256",
    }

    payload = {
        "commands": [
            {
                "code": command,
                "value": params
            }
        ]
    }

    url = f"{apiurl}{url_path}"
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code != 200:
        raise Exception(f"Failed to control device: {response.text}")

    return response.json()

@tuyablue.route('/change_color', methods=['POST'])#flask routes to handle requests
def change_color_route():
    data = request.json
    device_id = data.get('device_id')
    color = data.get('color')  

    try:
        change_color(device_id, color)
        return {"status": "success"}, 200
    except Exception as e:
        return {"status": "error", "message": str(e)}, 500


@tuyablue.route('/change_brightness', methods=['POST'])#flask routes to handle requests
def change_brightness_route():
    data = request.json
    device_id = data.get('device_id')
    brightness = data.get('brightness')

    try:
        change_brightness_level(device_id, brightness)
        return {"status": "success"}, 200
    except Exception as e:
        return {"status": "error", "message": str(e)}, 500


@tuyablue.route('/change_power_state', methods=['POST'])
def change_power_state_route():
    data = request.json
    device_id = data.get('device_id')
    state = data.get('state')  
    password = data.get('password') 

    device = db.session.execute(
        text("SELECT * FROM devices WHERE tuya_device_id = :device_id"),
        {"device_id": device_id}
    ).fetchone()

    if not device or not check_password_hash(device.password, password):
        return {"status": "error", "message": "Wrong password for the device."}, 403

    try:
        change_power_state(device_id, state)
        return {"status": "success"}, 200
    except Exception as e:
        return {"status": "error", "message": str(e)}, 500


@tuyablue.route('/set_device_settings', methods=['POST'])#flask routes to handle requests
def set_device_settings():
    data = request.json
    device_id = data.get('device_id')
    color = data.get('color')
    brightness = data.get('brightness')
    password = data.get('password')

    device = db.session.execute(
        text("SELECT * FROM devices WHERE tuya_device_id = :device_id"),
        {"device_id": device_id}
    ).fetchone()

    if not device or not check_password_hash(device.password, password):
        return {"status": "error", "message": "Wrong password for the device."}, 403

    try:
        change_color(device_id, color)
        change_brightness_level(device_id, brightness)
        return {"status": "success"}, 200
    except Exception as e:
        return {"status": "error", "message": str(e)}, 500