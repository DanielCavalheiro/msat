"""This module contains functions for encrypting and hashing data."""

import base64
import hashlib
import hmac
from Crypto.Cipher import AES
from pyope.ope import OPE, ValueRange

from utils.token_utils import AbsToken, EncToken


# ------------------------------------ SSE ----------------------------------- #

def generate_key(password):
    """Generates a 256-bit key from a password."""
    hasher = hashlib.sha256()
    hasher.update(password.encode())
    return hasher.digest()


def encrypt_sse(data, password):
    """Encrypts data using deterministic AES in SIV mode."""
    cipher = AES.new(password, AES.MODE_SIV)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(base64.b64encode(ciphertext + tag)).decode("utf-8")


# Here for testing purposes and will not be used in the final implementation
def decrypt_sse(encrypted_data, password):
    """Decrypts data using deterministic AES in SIV mode."""
    cipher = AES.new(password, AES.MODE_SIV)
    ciphertext, tag = encrypted_data[:-16], encrypted_data[-16:]
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_data.decode()


# ------------------------------------ OPE ----------------------------------- #

def encrypt_ope(data, password):
    """Encrypts data using Order Preserving Encryption."""
    ope = OPE(password, in_range=ValueRange(-1, 2**15-2),
              out_range=ValueRange(0, 2**31-1))
    return ope.encrypt(int(data))


def decrypt_ope(encrypted_data, password):
    """Decrypts data using Order Preserving Encryption."""
    ope = OPE(password, in_range=ValueRange(-1, 2**15-2),
              out_range=ValueRange(0, 2**31-1))
    return ope.decrypt(encrypted_data)


# ----------------------------------- HASH ----------------------------------- #

def hash_it(data):
    """Hashes data using SHA-256."""
    h = hashlib.sha256()
    h.update(data.encode())
    return h.hexdigest()


def hmac_it(data, password):
    """Hashes data using HMAC with SHA."""
    h = hmac.new(password, data.encode(), hashlib.sha1)
    return base64.b64encode(base64.b64encode(h.hexdigest().encode())).decode("utf-8")

# ----------------------------- testing purposes ----------------------------- #


def decrypt_token(token: EncToken, secret_password):
    """Decrypts an encrypted token."""
    token_type = decrypt_sse(base64.b64decode(
        base64.b64decode(token.token_type)), secret_password)
    line_num = decrypt_sse(base64.b64decode(
        base64.b64decode(token.line_num)), secret_password)
    position = decrypt_ope(token.token_pos, secret_password)
    depth = decrypt_ope(token.depth, secret_password)
    order = decrypt_ope(token.order, secret_password)
    flow_type = decrypt_ope(token.flow_type, secret_password)
    return AbsToken(token_type, line_num, position, depth, order, flow_type)
