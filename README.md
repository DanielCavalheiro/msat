# MSAT (Masked Static Analysis Tool)

MSAT (Masked Static Analysis Tool) is an innovative static analysis tool designed for PHP codebases that prioritizes code confidentiality. Unlike traditional static analysis tools, MSAT first encrypts your codebase and then performs vulnerability detection on the encrypted code. The results are also encrypted, ensuring that only the person who initiated the encryption can decrypt and view the findings.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)

## Installation

### Prerequisites

- [Python](https://www.python.org/) 3.8+

### Steps

1. Clone the repository / Download zip and extract it
    ```bash
    git clone https://github.com/DanielCavalheiro/msat.git
    ```
2. Navigate into the project directory
    ```bash
    cd msat
    ```
4. Create a Virtual Enviorment
   ```bash
   python -m venv venv
   ```
5. Activate the Virtual Enviorment
   On macOS and Linux
   ```bash
   source venv/bin/activate
   ```
   On Windows
   ```bash
   venv\Scripts\activate
   ```
6. Install dependencies
    ```bash
    pip install -r requirements.txt
    ```

## Usage

There 2 diferent ways to run the project. Through the graphical interface or using the comand line.

> [!IMPORTANT]
> In order for any of the following commands to work they must be executed in the root directory of the project and with the Virtual Enviorment activated.

### GUI

Probably the simpler way to run the project.

```bash
python main.py
```
If done correctly a interface will appear. There are 3 different tabs in the interface: client side, auditor side, decrypt retsult. Each should be executed in sequence to get a result.

### Command Line

The alternative way to run the project is through the commandline. In the scripts directory there can be found:
  - client_side.py : the script to run the client side;
  - auditor_side.py : the scrip to run the auditor side;
  - decrypt_result : the script to decrypt the auditor side output;
  - all_in_one.py : the script that runs the whole tool in one go.

#### Client Side

```bash
python scripts/client_side.py <secret_password> <shared_password> <dir> <output_dir> 
```
  - secrete_password : the password only the client should know
  - shared_password : the password that allows the tool to find vulnerabilities without revealing them
  - dir : the directory of the code repo
  - output_dir : the directory where the clien_side_output file will be saved to be later used by the auditor side

#### Auditor Side

```bash
python scripts/auditor_side.py <shared_password> <file> <vulnerability_to_detect> <output_dir>
```
 - shared_password : the password that allows the tool to find vulnerabilities without revealing them
 - file : path to the output file of the client side
 - vulnerability_to_detect : type of vulnerability to detect (either XSS or SQLI)
 - output_dir : the directory where the auditor_side_output file will be saved to be later decrypted by the client

#### Decrypt Result

```bash
python scripts/decrypt_result.py <secret_password> <shared_password> <file>
```
  - secrete_password : the password only the client should know
  - shared_password : the password that allowed the tool to find vulnerabilities without revealing them
  - file : the path to the output file of the auditor side

#### All In One

```bash
python scripts/all_in_one.py <secret_password> <shared_password> <dir> <output_dir> <vulnerability_to_detect>
```
  - secrete_password : the password only the client should know
  - shared_password : the password that allows the tool to find vulnerabilities without revealing them
  - dir : the directory of the code repo
  - output_dir : directory where the clien_side_output file and auditor_side_output file will be saved
  - vulnerability_to_detect : type of vulnerability to detect (either XSS or SQLI)


