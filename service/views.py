"""
Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.

SPDX-License-Identifier: BSD-3-Clause
"""
import logging

from rest_framework import mixins, status, viewsets
from rest_framework.response import Response

from service.models import Job
from service.serializer import JobSerializer
from service.tasks import job_process

log = logging.getLogger(__name__)


class JobViewSet(
    mixins.CreateModelMixin,
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    viewsets.GenericViewSet,
):
    queryset = Job.objects.all()
    serializer_class = JobSerializer

    def perform_create(self, serializer):
        serializer.save()

        job_process.delay(
            serializer.validated_data.get("build"), serializer.records
        )
