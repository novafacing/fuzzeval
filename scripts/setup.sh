#!/bin/bash

# This should be run on the host system to prep it to run AFL++

echo core | sudo tee /proc/sys/kernel/core_pattern
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
