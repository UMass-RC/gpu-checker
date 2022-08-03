#!/bin/bash
while 1
do
python3 gpu_checker.py &> ../logs/gpu_checker_looper.log
sleep 5
done