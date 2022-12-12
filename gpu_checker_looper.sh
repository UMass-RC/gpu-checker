#!/bin/bash

WHICH_PYTHON="./gpu_checker_venv/bin/python"
LOGFILE="/opt/logs/gpu_checker_looper.log"

fail_not_exists(){
    if [ ! -e $1 ]; then
        echo "$1 doesn't exist!"
        exit 1
    fi
}

fail_not_exists $WHICH_PYTHON
fail_not_exists ./gpu_checker.py
fail_not_exists ./send_email.py

while true; do
    $WHICH_PYTHON ./gpu_checker.py &> $LOGFILE
    if [ ! $? -eq 0 ]; then
        tail -n 50 $LOGFILE | $WHICH_PYTHON ./send_email.py "gpu-checker died!"
    fi
    sleep 5
done