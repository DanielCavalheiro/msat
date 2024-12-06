# MSAT (Masked Static Analysis Tool)

MSAT (Masked Static Analysis Tool) is an innovative static analysis tool designed for PHP codebases that prioritizes code confidentiality. Unlike traditional static analysis tools, MSAT first encrypts your codebase and then performs vulnerability detection on the encrypted code. The results are also encrypted, ensuring that only the person who initiated the encryption can decrypt and view the findings. It can also be run without encryption.

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

3. Create a Virtual Environment

    ```bash
   python -m venv venv
   ```

4. Activate the Virtual Environment

    On macOS and Linux
   ```bash
   source venv/bin/activate
   ```
   On Windows
   ```bash
   venv\Scripts\activate
   ```

5. Install dependencies

    ```bash
    pip install -r requirements.txt
    ```

## Usage

There are two different ways to run the project. Through the graphical interface or using the command line.

> [!IMPORTANT]
> In order for any of the following commands to work they must be executed in the root directory of the project and with the Virtual Environment activated.

There is an `examples` directory which contains examples of vulnerable PHP code that can be used to test the tool with the following commands.

### GUI

Probably the simplest way to run the project.

```bash
python gui.py
```
If done correctly an interface will appear. There are 3 different tabs in the interface: client side, auditor side, decrypt result. Each should be executed in sequence to get a result.

### Command Line

The alternative way to run the project is through the command line. In the `scripts` directory one can find:
  - `client_side.py` : the script to run the client side;
  - `auditor_side.py` : the script to run the auditor side;
  - `decrypt_result` : the script to decrypt the auditor side output;
  - `run_all.py` : the script that runs the whole tool in one go.

#### Client Side

```bash
python client_side.py [-h] --secret_password SECRET_PASSWORD --shared_password SHARED_PASSWORD --project_dir PROJECT_DIR [--output_dir OUTPUT_DIR]
```
  - `-h`, `--help`: help message and exit
  - `--secret_password SECRET_PASSWORD`, `-sep SECRET_PASSWORD` : the password only the client should know used to encrypt critical data
  - `--shared_password SHARED_PASSWORD`, `-shp SHARED_PASSWORD` : the password that allows the tool to find vulnerabilities without revealing them
  - `--project_dir PROJECT_DIR`, `-p PROJECT_DIR` : the directory of the project to be analyzed
  - `--output_dir OUTPUT_DIR`, `-o OUTPUT_DIR` : the directory where the `client_side_output` file will be saved to be later used by the auditor side. If not provided the output will be saved in the current directory.

#### Auditor Side

```bash
python auditor_side.py [-h] --shared_password SHARED_PASSWORD [--file_path FILE_PATH] --vuln_type {xss,sqli} [--output_dir OUTPUT_DIR]
```
 - `-h`, `--help`: help message and exit
 - `--shared_password SHARED_PASSWORD`, `-shp SHARED_PASSWORD` : the password that allows the tool to find vulnerabilities without revealing them
 - `--file_path FILE_PATH`, `-f FILE_PATH` : path to the output file of the client side. If not provided the tool will look for the file in the current directory
 - `--vuln_type {xss,sqli}`, `-v {xss,sqli}` : type of vulnerability to detect (either xss or sqli)
 - `--output_dir OUTPUT_DIR`, `-o OUTPUT_DIR` : the directory where the auditor_side_output file will be saved to be later decrypted by the client. If not provided the output will be saved in the current directory.

#### Decrypt Result

```bash
python decrypt_result.py [-h] --secret_password SECRET_PASSWORD --shared_password SHARED_PASSWORD [--file_path FILE_PATH]
```
  - `-h`, `--help`: help message and exit
  - `--secret_password SECRET_PASSWORD`, `-sep SECRET_PASSWORD` : the password only the client should know
  - `--shared_password SHARED_PASSWORD`, `-shp SHARED_PASSWORD` : the password that allowed the tool to find vulnerabilities without revealing them
  - `--file_path FILE_PATH`, `-f FILE_PATH` : the path to the output file of the auditor side. If not provided the tool will look for the file in the current directory.

#### Run All

```bash
python run_all.py [-h] --project_dir PROJECT_DIR [--no-encryption] --vuln_type {xss,sqli} [--secret_password SECRET_PASSWORD] [--shared_password SHARED_PASSWORD]

```
  - `-h`, `--help`: help message and exit
  - `--project_dir PROJECT_DIR`, `-p PROJECT_DIR` : the directory of the project to be analyzed.
  - `--no-encryption`, `-ne` : flag to run the tool without encryption. If not provided then encryption will be used.
  - `--vuln_type {xss,sqli}`, `-v {xss,sqli}` : type of vulnerability to detect (either xss or sqli).
  - `--secret_password SECRET_PASSWORD`, `-sep SECRET_PASSWORD` : The secret password to encrypt critical data. Can be omitted if no-encryption flag is provided.
  - `--shared_password SHARED_PASSWORD`, `-shp SHARED_PASSWORD` : The shared password to encrypt data used in detection. Can be omitted if no-encryption flag is provided.



