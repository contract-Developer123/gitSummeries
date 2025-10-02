#!/bin/bash
set -e

echo "👋 Hello $INPUT_WHO_TO_GREET"

echo "📦 Generating Secrets..."

  cd /app
  node secret-scanner.js