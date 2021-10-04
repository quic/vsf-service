# Copyright (c) 2019-2021 Qualcomm Technologies, Inc.
# All Rights Reserved.
# Confidential and Proprietary - Qualcomm Technologies, Inc.
FROM python:3.9.7-slim-bullseye
LABEL maintainer="qosp.devops@qti.qualcomm.com"

ADD https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh /usr/local/bin

RUN chmod +x /usr/local/bin/wait-for-it.sh

# Set application work directory
WORKDIR /app
ENV PYTHONBUFFERED=1 \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    PATH="${PATH}:~/.local/bin"

# Install python dependencies
COPY requirements.txt /app
RUN pip install --no-cache-dir --user -r /app/requirements.txt

# Setup application
COPY run_app.sh run_worker.sh manage.py vsf service /app/
