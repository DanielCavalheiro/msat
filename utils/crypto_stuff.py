"""This module contains functions for encrypting and hashing data."""

import hashlib
import hmac
from Crypto.Cipher import AES
from pyope.ope import OPE


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
    return ciphertext + tag


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
    ope = OPE(password)
    return ope.encrypt(int(data))


def decrypt_ope(encrypted_data, password):
    """Decrypts data using Order Preserving Encryption."""
    ope = OPE(password)
    return ope.decrypt(encrypted_data)


# ----------------------------------- HASH ----------------------------------- #

def hash_it(data):
    """Hashes data using SHA-256."""
    h = hashlib.sha256()
    h.update(data.encode())
    return h.hexdigest()


def hmac_it(data, password):
    """Hashes data using HMAC with SHA-256."""
    h = hmac.new(password.encode(), data.encode(), hashlib.sha256)
    return h.hexdigest()
