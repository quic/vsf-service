"""
Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.

SPDX-License-Identifier: BSD-3-Clause
"""
from service import views

from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r"jobs", views.JobViewSet)

urlpatterns = router.urls
