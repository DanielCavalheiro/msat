"""This module contains functions for encrypting and hashing data."""

import base64
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from pyope.ope import OPE, ValueRange


# ------------------------------------ SSE ----------------------------------- #

def generate_key(password):
    """Generates a 256-bit key from a password."""
    hasher = hashlib.sha256()
    hasher.update(password.encode())
    return hasher.digest()


def encrypt_sse(data, password):
    """Encrypts data using deterministic AES in SIV mode."""
    cipher = AES.new(password, AES.MODE_SIV)
    # Add padding, 25 so that it is the same size as hmac
    padded_data = pad(data.encode(), 25)
    ciphertext, tag = cipher.encrypt_and_digest(padded_data)
    return base64.b64encode(base64.b64encode(ciphertext + tag)).decode("utf-8")


# Here for testing purposes and will not be used in the final implementation?
def decrypt_sse(encrypted_data, password):
    """Decrypts data using deterministic AES in SIV mode."""
    cipher = AES.new(password, AES.MODE_SIV)
    ciphertext, tag = encrypted_data[:-16], encrypted_data[-16:]
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    # Remove padding, 25 so that it is the same size as hmac
    unpadded_data = unpad(decrypted_data, 25)
    return unpadded_data.decode()


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


# ------------------------------------ GCM ----------------------------------- #

def encrypt_gcm(data, password):
    """Encrypts data using AES in GCM mode."""
    cipher = AES.new(password, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(nonce + ciphertext + tag).decode("utf-8")


def decrypt_gcm(encrypted_data, password):
    """Decrypts data using AES in GCM mode."""
    decoded_data = base64.b64decode(encrypted_data)
    nonce, ciphertext, tag = decoded_data[:16], decoded_data[16:-
                                                             16], decoded_data[-16:]
    cipher = AES.new(password, AES.MODE_GCM, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_data.decode()


# ----------------------------------- HASH ----------------------------------- #

def hash_it(data):
    """Hashes data using SHA-256."""
    h = hashlib.sha256()
    h.update(data.encode())
    return h.hexdigest()


def hmac_it(data, password):
    """Hashes data using HMAC with SHA."""
    h = hmac.new(password, data.encode(),
                 hashlib.sha1)  # FIXME SHA1 might need to be changed
    return base64.b64encode(base64.b64encode(h.hexdigest().encode())).decode("utf-8")


def populate_special_tokens(shared_password):
    """Populate the special tokens"""
    return {
        "INPUT": hmac_it("INPUT", shared_password),
        "XSS_SENS": hmac_it("XSS_SENS", shared_password),
        "XSS_SANF": hmac_it("XSS_SANF", shared_password),
        "SQLI_SENS": hmac_it("SQLI_SENS", shared_password),
        "SQLI_SANF": hmac_it("SQLI_SANF", shared_password),
        "FUNC_CALL": hmac_it("FUNC_CALL", shared_password),
        "RETURN": hmac_it("RETURN", shared_password),
        "ARGS": hmac_it("ARGS", shared_password),
        "IMPORTS": hmac_it("IMPORTS", shared_password),
    }
