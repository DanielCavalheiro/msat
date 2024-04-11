from components.abstractor import Abstractor


def tokenize(file):
    try:
        data = open(file, 'r', encoding='utf-8')
    except FileNotFoundError:
        print("File not found")
    else:
        with data:
            lexer = Abstractor()
            lexer.input(data.read())

            while True:
                token = lexer.token()
                if not token:
                    break
                print(token)


if __name__ == '__main__':
    FILE = "/home/dani/tese/hollingworth_app/xss2.php"
    tokenize(FILE)
