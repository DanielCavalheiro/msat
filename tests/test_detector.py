"""Tests the detector component individually"""

from utils.token_utils import ResultToken, token_decoder, result_decoder
import utils.crypto_stuff as crypto_stuff
from components.detector import Detector
from components.encryptor import Encryptor
from components.abstractor import Abstractor
from components.correlator import Correlator
from tests.old_detector import OldDetector
import base64
import json
import os
import time
import psutil

ENCRYPT_FLAG = False
SECRET_PASSWORD = crypto_stuff.generate_key("secret_password")
SHARED_PASSWORD = crypto_stuff.generate_key("shared_password")
DETECTING = "SQLI"
DIR = "/home/dani/Downloads/zipec-0.32"


def decrypt_token(token, secret_password):
    """Decrypts an encrypted token."""
    if token.token_type == special_tokens["INPUT"]:
        token_type = "INPUT"
    elif token.token_type == special_tokens["FUNC_CALL"]:
        token_type = "FUNC_CALL"
    else:
        token_type = crypto_stuff.decrypt_sse(
            base64.b64decode(token.token_type), secret_password)
    line_num = crypto_stuff.decrypt_sse(
        base64.b64decode(token.line_num), secret_password)
    position = crypto_stuff.decrypt_ope(token.token_pos, secret_password)
    file_path = crypto_stuff.decrypt_gcm(
        token.file_path, secret_password)
    if token.arguments is not None:
        scope_name = crypto_stuff.decrypt_sse(
            base64.b64decode(token.scope_name), secret_password)
        arguments = []
        for arg in token.arguments:
            arguments.append(decrypt_token(arg, secret_password))
        return ResultToken(token_type, line_num, position, file_path, scope_name, arguments)
    elif token.scope_name is not None:
        scope_name = crypto_stuff.decrypt_sse(
            base64.b64decode(token.scope_name), secret_password)
        return ResultToken(token_type, line_num, position, file_path, scope_name)

    return ResultToken(token_type, line_num, position, file_path)

#process = psutil.Process(os.getpid())
#cpu_usage = process.cpu_percent(1)

#cpu_usage = process.cpu_percent()

#pre_enc_time_start = time.time()

all_in_one_time_start = time.time()

data_structure = {}
lexer = Abstractor()

found_php_files = False
for root, dirs, files in os.walk(DIR):
    for file in files:
        if file.endswith('.php'):
            found_php_files = True
            php_file = os.path.join(root, file)
            with open(php_file, "r", encoding="latin-1") as data:
                scope = php_file
                lexer.file_name = scope
                lexer.input(data.read())
                lexer.lineno = 1
                correlator = Correlator(lexer, data_structure, 0, 0, scope, {}, php_file)
                correlator.correlate()



if not found_php_files:
    print(f"No PHP files found in {DIR}")
    exit(0)

#re_enc_time_end = time.time()
#re_enc_time_total = (pre_enc_time_end - pre_enc_time_start) * 1000
#rint(f"Pre-encryption time: {pre_enc_time_total:.2f} milliseconds")

#encryption_time_start = time.time()



encryptor = Encryptor(ENCRYPT_FLAG)
encryptor.encrypt_data_structure(
    data_structure, SECRET_PASSWORD, SHARED_PASSWORD)

#encryption_time_end = time.time()
#encryption_time_total = (encryption_time_end - encryption_time_start) * 1000
#print(f"Encryption time: {encryption_time_total:.2f} milliseconds")

detection_time_start = time.time()
vulnerable_paths = []


with open("client_side_output", "r", encoding="utf-8") as f:
    detector = None
    if ENCRYPT_FLAG:
        decrypted_data = crypto_stuff.decrypt_gcm(f.read(), SHARED_PASSWORD)
        encrypted_ds = json.loads(decrypted_data, object_hook=token_decoder)
        detector = Detector(encrypted_ds, SHARED_PASSWORD, ENCRYPT_FLAG)
    else:
        not_encrypted_ds = json.loads(f.read(), object_hook=token_decoder)
        detector = OldDetector(not_encrypted_ds, SHARED_PASSWORD, ENCRYPT_FLAG)

    detector.set_vuln_type(DETECTING)
    vulnerable_paths = detector.detect_vulnerability()

encryptor.encrypt_result(vulnerable_paths, SHARED_PASSWORD)

#detection_time_end = time.time()
#detection_time_total = (detection_time_end - detection_time_start) * 1000
#print(f"Detection time: {detection_time_total:.2f} milliseconds")

#decryption_time_start = time.time()

#cpu_usage = process.cpu_percent()


with open("auditor_side_output", "r", encoding="utf-8") as f:
    if ENCRYPT_FLAG:
        decrypted_data = crypto_stuff.decrypt_gcm(f.read(), SHARED_PASSWORD)
    else:
        decrypted_data = f.read()
    vulnerable_paths = json.loads(decrypted_data, object_hook=result_decoder)
    special_tokens = crypto_stuff.populate_special_tokens(SHARED_PASSWORD)
    path_counter = 0
    for path in vulnerable_paths:
        path_counter += 1
        print(f"\nVulnerable path {path_counter}:")
        for token in path:
            if ENCRYPT_FLAG:
                print("\t" + str(decrypt_token(token, SECRET_PASSWORD)))
            else:
                print("\t" + str(token))

#decryption_time_end = time.time()
#decryption_time_total = (decryption_time_end - decryption_time_start) * 1000
#print(f"Decryption time: {decryption_time_total:.2f} milliseconds")
all_in_one_time_end = time.time()
all_in_one_time_total = (all_in_one_time_end - all_in_one_time_start) * 1000
print(f"Total time: {all_in_one_time_total:.2f} milliseconds")

# Runtime metrics
#memory_usage = process.memory_info().rss / (1024 * 1024)  # Convert bytes to MB

# Storage metrics (if applicable)
#client_side_file_size = os.path.getsize("client_side_output") / (1024)  # KB
#auditor_side_file_size = os.path.getsize("auditor_side_output") / (1024)  # KB

#print(f"CPU usage: {cpu_usage:.2f}%")
#print(f"Memory usage: {memory_usage:.2f} MB")
#print(f"Client-side output file size: {client_side_file_size:.2f} KB")
#print(f"Auditor-side output file size: {auditor_side_file_size:.2f} KB")


