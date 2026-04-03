#!/bin/sh

ANCHOR="EIPPF_SAMPLE_ANCHOR_SHELL_SCRIPT"
INPUT_VALUE="${1:-19}"

if [ $((INPUT_VALUE % 2)) -eq 0 ]; then
  RESULT=$((INPUT_VALUE * 3 + 5))
else
  RESULT=$((INPUT_VALUE * 2 + 7))
fi

echo "${ANCHOR}:${RESULT}"
