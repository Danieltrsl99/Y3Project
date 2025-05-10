from dotenv import load_dotenv
import os

# Load .env file for api keys
load_dotenv()

apiurl = os.getenv("apiurl", "https://openapi.tuyaeu.com")  # Impopartant to set to correct region check tuya docs (eu) is central region
accessid = os.getenv("accessid")
accesskey = os.getenv("accesskey")
userid = os.getenv("userid")


if not accessid or not accesskey or not userid:
    raise ValueError("Missing api keys in .env file.")
