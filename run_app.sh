#!/bin/bash
# Copyright (c) 2019 Qualcomm Technologies, Inc.
# All Rights Reserved.
# Confidential and Proprietary - Qualcomm Technologies, Inc.

NON_PROD=$1

# prepare init migration
python manage.py makemigrations
# migrate db, so we have the latest db schema
python manage.py migrate
# copy static assets into vsf_service/vsf_service/static
python manage.py collectstatic --no-input

if [ "$NON_PROD" = true ] ; then
  # start development server on public ip interface, on port 8000
  echo "Starting Django development server..."
  python manage.py runserver 0.0.0.0:8000
else
  # start server on public ip interface, on port 8000
  echo "Starting gunicorn..."
  gunicorn vsf.wsgi -b :8000
fi
