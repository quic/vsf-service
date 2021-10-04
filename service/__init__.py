"""
Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.

SPDX-License-Identifier: BSD-3-Clause
"""
from .celery import app as celery_app

__all__ = ("celery_app",)
