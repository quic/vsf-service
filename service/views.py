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

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        job_process.delay(
            serializer.validated_data.get("build"), serializer.records
        )

        headers = self.get_success_headers(serializer.data)

        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )
