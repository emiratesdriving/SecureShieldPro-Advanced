#!/bin/bash

# Change to the backend directory
cd /home/edc1840/Music/EmiratesDriving/backend

# Set PYTHONPATH to include the backend directory  
export PYTHONPATH=/home/edc1840/Music/EmiratesDriving/backend:$PYTHONPATH

# Start the backend
/home/edc1840/Music/.venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
