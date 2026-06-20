#!/bin/bash
# run_nids.sh — automates the NIDS detection pipeline

echo "=============================="
echo "  NIDS Automated Pipeline"
echo "  $(date)"
echo "=============================="

# Check data files exist
if [ ! -f "data/monday.csv" ]; then
  echo "[ERROR] data/monday.csv not found. Please download the dataset first."
  exit 1
fi

if [ ! -f "data/friday.csv" ]; then
  echo "[ERROR] data/friday.csv not found. Please download the dataset first."
  exit 1
fi

# Run the pipeline
echo "[INFO] Starting detection pipeline..."
python main.py

# Check exit status
if [ $? -eq 0 ]; then
  echo "[INFO] Pipeline completed successfully."
  echo "[INFO] Check the alerts/ folder for results."
else
  echo "[ERROR] Pipeline failed. Check the output above."
  exit 1
fi
