import os
import json
from datetime import datetime, timedelta, timezone
from werkzeug.security import generate_password_hash, check_password_hash

SETTINGS_PATH = os.path.join(os.path.dirname(__file__), 'instance', 'admin_settings.json')


def _ensure_instance_dir():
    inst = os.path.dirname(SETTINGS_PATH)
    if not os.path.exists(inst):
        os.makedirs(inst, exist_ok=True)


def load_settings():
    _ensure_instance_dir()
    if not os.path.exists(SETTINGS_PATH):
        return {}
    try:
        with open(SETTINGS_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def save_settings(data: dict):
    _ensure_instance_dir()
    with open(SETTINGS_PATH, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)


def get_admin_username():
    s = load_settings()
    return s.get('username')


def check_admin_password(plain_password: str) -> bool:
    s = load_settings()
    pwd_hash = s.get('password_hash')
    if not pwd_hash:
        return False
    return check_password_hash(pwd_hash, plain_password)


def set_admin_credentials(username: str, plain_password: str):
    s = load_settings()
    s['username'] = username
    s['password_hash'] = generate_password_hash(plain_password)
    save_settings(s)


def get_mobile():
    s = load_settings()
    return s.get('mobile')


def set_mobile(mobile: str):
    s = load_settings()
    s['mobile'] = mobile
    save_settings(s)


def get_require_otp() -> bool:
    s = load_settings()
    return bool(s.get('require_otp', False))


def set_require_otp(val: bool):
    s = load_settings()
    s['require_otp'] = bool(val)
    save_settings(s)


def set_otp(code: str, valid_minutes: int = 5):
    s = load_settings()
    expires = (datetime.now(timezone.utc) + timedelta(minutes=valid_minutes)).isoformat()
    s['otp'] = {'code': code, 'expires': expires}
    save_settings(s)


def verify_otp(code: str) -> bool:
    s = load_settings()
    otp = s.get('otp')
    if not otp:
        return False
    try:
        expires = datetime.fromisoformat(otp.get('expires'))
    except Exception:
        return False
    if datetime.now(timezone.utc) > expires:
        return False
    return otp.get('code') == code


def clear_otp():
    s = load_settings()
    if 'otp' in s:
        s.pop('otp')
        save_settings(s)
