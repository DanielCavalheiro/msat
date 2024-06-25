import sys
import os
from components.abstractor import Abstractor

DIR = "/home/dani/tese/hollingworth_app/testing_dir"
php_files = []
for root, dirs, files in os.walk(DIR):
    for file in files:
        if file.endswith('.php'):
            php_files.append(os.path.join(root, file))

lexer = Abstractor()
for file in php_files:
    with open(file, "r", encoding="utf-8") as data:
        lexer.file_name = os.path.basename(file)
        lexer.input(data.read())
        lexer.lineno = 1

        while True:
            token = lexer.token()
            if not token:
                break
            print(token)
