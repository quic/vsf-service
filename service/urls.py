"""
Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.

SPDX-License-Identifier: BSD-3-Clause
"""
from django.conf.urls import include
from django.urls import path, re_path

from service import views

from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r"jobs", views.JobViewSet)
router.register(
    r"jobs/(?P<job_id>\d+)/reports",
    views.JobReportViewSet,
    basename="jobs-reports",
)

urlpatterns = [
    re_path(r"^", include(router.urls)),
]
