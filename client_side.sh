#!/bin/bash

# Check if the required number of arguments is provided
if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <secret_password> <shared_password> <target_dir> [output_dir]"
    exit 1
fi

# Assign input arguments to variables
SECRET_PASSWORD=$1
SHARED_PASSWORD=$2
TARGET_DIR=$3
OUTPUT_DIR=${4:-.}

# Export variables to be used in the Python script
export SECRET_PASSWORD
export SHARED_PASSWORD
export TARGET_DIR
export OUTPUT_DIR

# Activate the Python virtual environment
source .venv/bin/activate

# Check if the virtual environment activation was successful
if [ $? -ne 0 ]; then
    echo "Error: Failed to activate virtual environment."
    exit 1
fi

# Run the Python script
python client_side.py "$SECRET_PASSWORD" "$SHARED_PASSWORD" "$TARGET_DIR" "$OUTPUT_DIR"

# Deactivate the Python virtual environment
deactivate