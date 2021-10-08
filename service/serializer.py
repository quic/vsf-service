"""
Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.

SPDX-License-Identifier: BSD-3-Clause
"""
import json
import logging
from json.decoder import JSONDecodeError

from django.core.files.uploadedfile import TemporaryUploadedFile
from rest_framework import serializers
from django.utils.translation import gettext_lazy as _

from service.models import Job, LocalFile, RemoteFile, Snippet, File

log = logging.getLogger(__name__)


class JobSerializer(serializers.ModelSerializer):
    file = serializers.FileField(write_only=True)
    status = serializers.ReadOnlyField(source="get_status_display")

    def create(self, validated_data):
        _ = validated_data.pop("file")

        return super().create(validated_data)

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation.pop("files")

        return representation

    def validate_file(self, value: TemporaryUploadedFile):
        log.info(f"Validating {value}")

        self.records = None
        try:
            self.records = json.load(value)
            if not isinstance(self.records, list):
                self.records = [self.records]
        except JSONDecodeError:
            log.warning(
                "Invalid json file format. Transform if the file is "
                "a list of json data."
            )

            try:
                value.seek(0)
                self.records = [
                    json.loads(record) for record in value.readlines()
                ]
            except JSONDecodeError:
                log.error(
                    "Trasform process failed. The file is not a list "
                    "of json data."
                )
                raise serializers.ValidationError(
                    f"{value} is not valid fossid output file."
                )
            except Exception:
                log.error(
                    f"Unhandled exception while validating {value}",
                    exc_info=True,
                )
                raise serializers.ValidationError(
                    f"Unhandled exception while validating {value}"
                )
            else:
                log.info(f"Successfully transformed data from {value}")
        except Exception:
            log.error(
                f"Unhandled exception while validating {value}", exc_info=True
            )
            raise serializers.ValidationError(
                "Unhandled exception while validating {value}"
            )

        return value

    def validate(self, data):
        if job := Job.objects.filter(
            build=data.get("build"),
            status__in=[
                Job.Status.CREATED,
                Job.Status.STARTED,
                Job.Status.COMPLETED,
            ],
        ).first():
            raise serializers.ValidationError(
                {
                    "error_message": _(
                        f"Job {job.id} has already been registered with build="
                        f"{job.build} with current "
                        f"status={job.get_status_display()}"
                    )
                }
            )

        return data

    class Meta:
        model = Job
        fields = "__all__"
        read_only_fields = (
            "created_at",
            "started_at",
            "ended_at",
            "status",
            "message",
            "files",
        )
