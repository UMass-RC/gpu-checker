#!/bin/bash
while true; do
    /opt/gpu_checker/gpu_checker_venv/bin/python /opt/gpu_checker/gpu_checker.py &> /opt/logs/gpu_checker_looper.log
    sleep 5
done
