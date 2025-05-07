# tuya.py
import time
import hmac
import hashlib
import requests
import logging
import json
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from config import ACCESS_ID, ACCESS_KEY, API_BASE_URL, USER_UID

logging.basicConfig(level=logging.DEBUG)

tuya_bp = Blueprint('tuya', __name__)

class TuyaAPIError(Exception):
    """Custom exception for Tuya API errors."""
    pass

cached_token = {"token": None, "expire_time": 0}

def get_token():
    global cached_token
    if cached_token["expire_time"] > time.time():
        return cached_token["token"]

    # Generate timestamp
    t = str(int(time.time() * 1000))

    # Construct the string to sign
    method = "GET"
    sign_url = "/v1.0/token?grant_type=1"
    content_hash = hashlib.sha256("".encode("utf-8")).hexdigest()  # Empty body hash
    string_to_sign = f"{method}\n{content_hash}\n\n{sign_url}"

    # Generate the signature
    sign_str = ACCESS_ID + t + string_to_sign
    sign = hmac.new(
        ACCESS_KEY.encode("utf-8"),
        sign_str.encode("utf-8"),
        hashlib.sha256
    ).hexdigest().upper()

    # Construct headers
    headers = {
        "t": t,
        "sign_method": "HMAC-SHA256",
        "client_id": ACCESS_ID,
        "sign": sign,
    }

    # Make the request
    response = requests.get(f"{API_BASE_URL}/v1.0/token?grant_type=1", headers=headers)
    logging.debug(f"Token Response Status Code: {response.status_code}")
    logging.debug(f"Token Response Text: {response.text}")

    if response.status_code != 200:
        raise TuyaAPIError(f"Failed to get token: {response.text}")

    # Parse the response
    try:
        data = response.json()
        logging.debug(f"Token Response JSON: {data}")
    except Exception as e:
        raise TuyaAPIError(f"Failed to parse token response: {response.text}") from e

    if "result" not in data:
        raise TuyaAPIError(f"Unexpected token response format: {data}")

    result = data["result"]
    cached_token["token"] = result["access_token"]
    cached_token["expire_time"] = time.time() + result["expire_time"] - 60
    return cached_token["token"]

def list_devices():
    token = get_token()
    t = str(int(time.time() * 1000))

    # Construct the string to sign
    method = "GET"
    url_path = f"/v1.0/users/{USER_UID}/devices"
    content_hash = hashlib.sha256("".encode("utf-8")).hexdigest()  # Empty body hash
    string_to_sign = f"{method}\n{content_hash}\n\n{url_path}"

    # Generate the signature
    sign_str = ACCESS_ID + token + t + string_to_sign
    sign = hmac.new(
        ACCESS_KEY.encode("utf-8"),
        sign_str.encode("utf-8"),
        hashlib.sha256
    ).hexdigest().upper()

    # Construct headers
    headers = {
        "client_id": ACCESS_ID,
        "access_token": token,
        "sign": sign,
        "t": t,
        "sign_method": "HMAC-SHA256",
    }

    # Make the request
    url = f"{API_BASE_URL}{url_path}"
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        raise TuyaAPIError(f"Failed to list devices: {response.text}")

    return response.json()["result"]

def get_device_specifications(device_id):
    token = get_token()
    t = str(int(time.time() * 1000))

    # Construct the string to sign
    method = "GET"
    url_path = f"/v1.0/devices/{device_id}/specifications"
    content_hash = hashlib.sha256("".encode("utf-8")).hexdigest()  # Empty body hash
    string_to_sign = f"{method}\n{content_hash}\n\n{url_path}"

    # Generate the signature
    sign_str = ACCESS_ID + token + t + string_to_sign
    sign = hmac.new(
        ACCESS_KEY.encode("utf-8"),
        sign_str.encode("utf-8"),
        hashlib.sha256
    ).hexdigest().upper()

    # Construct headers
    headers = {
        "client_id": ACCESS_ID,
        "access_token": token,
        "sign": sign,
        "t": t,
        "sign_method": "HMAC-SHA256",
    }

    # Make the request
    url = f"{API_BASE_URL}{url_path}"
    response = requests.get(url, headers=headers)

    logging.debug(f"Response Status Code: {response.status_code}")
    logging.debug(f"Response Text: {response.text}")

    if response.status_code != 200:
        raise TuyaAPIError(f"Failed to get device specifications: {response.text}")

    return response.json()

def change_color(device_id, color):
    """Change the color of a device."""
    token = get_token()
    t = str(int(time.time() * 1000))

    # Fetch device specifications to determine the correct DP code
    specs = get_device_specifications(device_id)
    functions = specs.get("result", {}).get("functions", [])
    dp_code = None

    # Ensure the device supports `colour_data_v2`
    if any(f["code"] == "colour_data_v2" for f in functions):
        dp_code = "colour_data_v2"
        # Convert RGB to HSV
        r, g, b = color
        r, g, b = r / 255.0, g / 255.0, b / 255.0
        max_c = max(r, g, b)
        min_c = min(r, g, b)
        delta = max_c - min_c

        # Calculate Hue
        if delta == 0:
            h = 0
        elif max_c == r:
            h = (60 * ((g - b) / delta) + 360) % 360
        elif max_c == g:
            h = (60 * ((b - r) / delta) + 120) % 360
        elif max_c == b:
            h = (60 * ((r - g) / delta) + 240) % 360

        # Calculate Saturation
        s = 0 if max_c == 0 else (delta / max_c) * 1000

        # Calculate Brightness
        v = max_c * 1000

        value = {
            "h": int(h),  # Hue (0–360)
            "s": int(s),  # Saturation (0–1000)
            "v": int(v),  # Brightness (0–1000)
        }
    else:
        raise TuyaAPIError("Device does not support `colour_data_v2` for color changing.")

    # Construct the commands
    commands = [
        {
            "code": "work_mode",  # Set the work mode to "colour"
            "value": "colour",
        },
        {
            "code": dp_code,  # Set the color using `colour_data_v2`
            "value": value,
        },
    ]

    # Construct the string to sign
    method = "POST"
    url_path = f"/v1.0/devices/{device_id}/commands"
    content = {"commands": commands}
    logging.debug(f"Sending color change command: {content}")
    content_hash = hashlib.sha256(json.dumps(content).encode("utf-8")).hexdigest()
    string_to_sign = f"{method}\n{content_hash}\n\n{url_path}"

    # Generate the signature
    sign_str = ACCESS_ID + token + t + string_to_sign
    sign = hmac.new(
        ACCESS_KEY.encode("utf-8"),
        sign_str.encode("utf-8"),
        hashlib.sha256
    ).hexdigest().upper()

    # Construct headers
    headers = {
        "client_id": ACCESS_ID,
        "access_token": token,
        "sign": sign,
        "t": t,
        "sign_method": "HMAC-SHA256",
    }

    # Make the request
    url = f"{API_BASE_URL}{url_path}"
    logging.debug(f"Sending request to {url} with headers {headers} and body {content}")
    response = requests.post(url, headers=headers, json=content)
    logging.debug(f"Response Status Code: {response.status_code}")
    logging.debug(f"Response Text: {response.text}")
    if response.status_code != 200:
        logging.error(f"Failed to change color: {response.text}")
        raise TuyaAPIError(f"Failed to change color: {response.text}")
    return response.json()

def change_power_state(device_id, state):
    """Turn the light on or off."""
    token = get_token()
    t = str(int(time.time() * 1000))
    url_path = f"/v1.0/devices/{device_id}/commands"
    content = {
        "commands": [
            {
                "code": "switch_led",  # DP code for turning the light on/off
                "value": state,
            }
        ]
    }

    # Generate the signature and send the command
    return send_tuya_command(url_path, content, token, t)

def change_brightness_level(device_id, brightness):
    """Adjust the brightness of the light."""
    token = get_token()
    t = str(int(time.time() * 1000))
    url_path = f"/v1.0/devices/{device_id}/commands"
    content = {
        "commands": [
            {
                "code": "bright_value_v2",  # DP code for brightness control
                "value": brightness,
            }
        ]
    }

    # Generate the signature and send the command
    return send_tuya_command(url_path, content, token, t)

def send_tuya_command(url_path, content, token, t):
    """Send a command to the Tuya API."""
    content_hash = hashlib.sha256(json.dumps(content).encode("utf-8")).hexdigest()
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
    response = requests.post(url, headers=headers, json=content)
    if response.status_code != 200:
        raise TuyaAPIError(f"Failed to send command: {response.text}")
    return response.json()

def control_device(device_id, command, params):
    token = get_token()
    t = str(int(time.time() * 1000))

    # Construct the string to sign
    method = "POST"
    url_path = f"/v1.0/devices/{device_id}/commands"
    content_hash = hashlib.sha256("".encode("utf-8")).hexdigest()  # Empty body hash
    string_to_sign = f"{method}\n{content_hash}\n\n{url_path}"

    # Generate the signature
    sign_str = ACCESS_ID + token + t + string_to_sign
    sign = hmac.new(
        ACCESS_KEY.encode("utf-8"),
        sign_str.encode("utf-8"),
        hashlib.sha256
    ).hexdigest().upper()

    # Construct headers
    headers = {
        "client_id": ACCESS_ID,
        "access_token": token,
        "sign": sign,
        "t": t,
        "sign_method": "HMAC-SHA256",
    }

    # Construct payload
    payload = {
        "commands": [
            {
                "code": command,
                "value": params
            }
        ]
    }

    # Make the request
    url = f"{API_BASE_URL}{url_path}"
    response = requests.post(url, json=payload, headers=headers)
    logging.debug(f"Tuya API Response: {response.json()}")
    if response.status_code != 200:
        raise Exception(f"Failed to control device: {response.text}")

    return response.json()