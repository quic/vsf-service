#!/bin/bash

# Copyright (c) 2019-2021 Qualcomm Technologies, Inc.
# All Rights Reserved.
# Confidential and Proprietary - Qualcomm Technologies, Inc.

NAME=${1:-default}
QUEUE=${2:-vsf.service}

# Run Celery worker for our project bot-service with Celery
# configuration stored in celery
echo "Starting Celery worker: $NAME $QUEUE..."
celery -A service.celery worker --without-mingle -n "$NAME"@%h -Q "$QUEUE" -l DEBUG