"""Module for the Encryptor component"""

from utils.different_tokens import AbsToken
from utils.different_tokens import EncToken
import utils.crypto_stuff as crypto_stuff


class Encryptor:
    """Encryptor component to encrypt data strcutur."""

    def __init__(self):
        pass

    def encrypt_data_structure(self, data_structure: dict, password):
        encrypted_ds = {}  # Encrypted data structure
        for key in data_structure:
            encrypted_key = crypto_stuff.encrypt_sse(key, password)
            values = data_structure[key]
            enc_assignors = []
            for value in values:
                enc_assignors.append(self.__encrypt_token(value, password))
            encrypted_ds[encrypted_key] = enc_assignors
        return encrypted_ds

    def encrypt_knowledge_source(self, knowledge_source, password):
        pass

    def __encrypt_token(self, token: AbsToken, password):
        token_type = crypto_stuff.encrypt_sse(token.token_type, password)
        position = crypto_stuff.encrypt_ope(token.token_pos, password)
        depth = crypto_stuff.encrypt_ope(token.depth, password)
        order = crypto_stuff.encrypt_ope(token.order, password)
        flow_type = crypto_stuff.encrypt_ope(token.flow_type, password)
        return EncToken(token_type, position, depth, order, flow_type)
