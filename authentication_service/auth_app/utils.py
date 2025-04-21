import jwt
import base64
import uuid
import bcrypt
from datetime import datetime
from django.conf import settings
from django.core.mail import send_mail

# Отладка
print("JWT module:", jwt)
print("JWT version:", getattr(jwt, '__version__', 'No version attribute'))
print("JWT file:", jwt.__file__)

def generate_access_token(user_id, ip_address):
    payload = {
        'user_id': str(user_id),
        'ip_address': ip_address,
        'exp': datetime.utcnow() + settings.ACCESS_TOKEN_LIFETIME,
        'iat': datetime.utcnow(),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def generate_refresh_token():
    return base64.urlsafe_b64encode(uuid.uuid4().bytes).decode('utf-8')


def hash_refresh_token(token):
    return bcrypt.hashpw(token.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def verify_refresh_token(token, token_hash):
    return bcrypt.checkpw(token.encode('utf-8'), token_hash.encode('utf-8'))


def send_ip_change_warning(user, old_ip, new_ip):
    subject = 'Warning: IP Address Changed'
    message = f"Your refresh token was used from a new IP address ({new_ip}). Previous IP was {old_ip}."
    send_mail(subject, message, settings.EMAIL_HOST_USER, [user.email])