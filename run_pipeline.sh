#!/bin/bash

LOG_FILE="pipeline_run_$(date +%Y%m%d_%H%M%S).txt"

echo "Starting full pipeline run..."
echo "Logging to $LOG_FILE"

python3 pipeline_runner.py \
  --db-path evidence_registry.db \
  --input-dir input_pcaps \
  --start-phase 1 \
  --end-phase 11 \
  --clear \
  --step5-workers 8 \
  2>&1 | tee "$LOG_FILE"

echo "Pipeline run completed."
echo "Log saved at: $LOG_FILE"