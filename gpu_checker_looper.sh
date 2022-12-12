#!/bin/bash
while true; do
    ./gpu_checker_venv/bin/python ./gpu_checker.py &> ../logs/gpu_checker_looper.log
    sleep 5
done
