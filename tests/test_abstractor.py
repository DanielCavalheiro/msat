"""Tests the abstracter component individually"""

import os
from components.abstractor import Abstractor

DIR = "/home/dani/tese/hollingworth_app/testing_dir"
php_files = []
for root, dirs, files in os.walk(DIR):
    for file in files:
        if file.endswith('.php'):
            php_files.append(os.path.join(root, file))

lexer = Abstractor()
found_php_files = False
for file in php_files:
    with open(file, "r", encoding="utf-8") as data:
        found_php_files = True
        lexer.file_name = os.path.basename(file)
        lexer.input(data.read())
        lexer.lineno = 1

        while True:
            token = lexer.token()
            if not token:
                break
            print(token)

if not found_php_files:
    print(f"No PHP files found in {DIR}")
    exit(0)
