#!/bin/bash

# BBPTS Performance Benchmarking Suite
# Compares BBPTS orchestration overhead to running tools sequentially.

echo "[*] Starting BBPTS Benchmarks"

TARGET_FILE="bench_targets.txt"
echo "example.com" > $TARGET_FILE
echo "hackerone.com" >> $TARGET_FILE

# Measure pure sequential execution
echo "[+] Running Sequential Execution Baseline..."
start_time=$(date +%s%N)
subfinder -dL $TARGET_FILE -o bench_subs.txt > /dev/null 2>&1
httpx -l bench_subs.txt -o bench_alive.txt > /dev/null 2>&1
nuclei -l bench_alive.txt -o bench_vulns.txt > /dev/null 2>&1
end_time=$(date +%s%N)
seq_duration=$((($end_time - $start_time)/1000000))
echo "    Sequential Time: ${seq_duration}ms"

# Measure BBPTS execution
echo "[+] Running BBPTS Execution..."
start_time=$(date +%s%N)
./bbpts -i $TARGET_FILE -silent > /dev/null 2>&1
end_time=$(date +%s%N)
bbpts_duration=$((($end_time - $start_time)/1000000))
echo "    BBPTS Time: ${bbpts_duration}ms"

# Cleanup
rm -f $TARGET_FILE bench_subs.txt bench_alive.txt bench_vulns.txt

echo "[*] Benchmarks Complete"
echo "Results:"
echo "Sequential: ${seq_duration}ms"
echo "BBPTS: ${bbpts_duration}ms"
