from dotenv import load_dotenv
import os

# Load .env file for api keys
load_dotenv()

API_BASE_URL = os.getenv("TUYA_ENDPOINT", "https://openapi.tuyaeu.com")  # Impopartant to set to correct region check tuya docs (eu) is central region
ACCESS_ID = os.getenv("TUYA_ACCESS_ID")
ACCESS_KEY = os.getenv("TUYA_ACCESS_KEY")
USER_UID = os.getenv("TUYA_USER_UID")

if not ACCESS_ID or not ACCESS_KEY or not USER_UID:
    raise ValueError("Missing Tuya API credentials in .env file.")
