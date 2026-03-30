import logging
from django.conf import settings

from .rsa_aes import rsa_decrypt, get_aes_crypto
from .gm import get_gm_sm4_ecb_crypto, sm2_decrypt


def rsa_decrypt_by_session_pkey(value, current_request):
    private_key_name = settings.SESSION_RSA_PRIVATE_KEY_NAME
    private_key = current_request.session.get(private_key_name)

    if not private_key or not value:
        return value

    try:
        value = rsa_decrypt(value, private_key)
    except Exception as e:
        logging.error('Decrypt field error: {}'.format(e))
    return value


def rsa_decrypt_session_password(value, current_request):
    cipher = value.split(':')
    if len(cipher) != 2:
        return value
    key_cipher, password_cipher = cipher
    if not all([key_cipher, password_cipher]):
        return value
    aes_key = rsa_decrypt_by_session_pkey(key_cipher, current_request)
    aes = get_aes_crypto(aes_key, 'ECB')
    try:
        password = aes.decrypt(password_cipher)
    except Exception as e:
        logging.error("Decrypt password error: {}, {}".format(password_cipher, e))
        return value
    return password


def gm_decrypt_by_session_pkey(value, current_request):
    private_key_name = settings.SESSION_RSA_PRIVATE_KEY_NAME
    private_key = current_request.session.get(private_key_name)
    if not private_key or not value:
        return value
    return sm2_decrypt(private_key, value)


def gm_decrypt_session_password(value, current_request):
    cipher = value.split(':')
    if len(cipher) != 2:
        return value
    key_cipher, password_cipher = cipher
    if not all([key_cipher, password_cipher]):
        return value
    sm4_key = gm_decrypt_by_session_pkey(key_cipher, current_request)
    crypto = get_gm_sm4_ecb_crypto(sm4_key)

    try:
        password = crypto.decrypt(password_cipher)
    except Exception as e:
        logging.error("Decrypt password error: {}, {}".format(password_cipher, e))
        return value
    return password


def decrypt_session_password(value):
    from jumpserver.utils import current_request
    if not current_request:
        return value
    
    if current_request.session.get('jms_gm_ssl') == '1':
        return gm_decrypt_session_password(value, current_request)
    else:
        return rsa_decrypt_session_password(value, current_request)
