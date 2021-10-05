"""
Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.

SPDX-License-Identifier: BSD-3-Clause
"""
import hashlib
import json
import logging
from typing import Any, Dict, List, Tuple

from django.utils import timezone
from django.utils.dateparse import parse_datetime

from service.celery import app
from service.models import CVE, File, Job, LocalFile, RemoteFile, Snippet
from service.utils import BuildLogAdapter, CVERecord

logger = logging.getLogger(__name__)


def _job_start(build: str) -> None:
    log = BuildLogAdapter(logger, {"build": build})

    job: Job = Job.objects.get(build=build)
    job.status = Job.Status.STARTED
    job.started_at = timezone.now()
    job.save()

    log.info(f"Job started at {job.started_at}")


def _job_complete(
    build: str, status: Tuple[int, Any], message: str = None
) -> None:
    log = BuildLogAdapter(logger, {"build": build})

    job: Job = Job.objects.get(build=build)
    job.status = status
    job.message = message
    job.ended_at = timezone.now()
    job.save()

    log.info(
        f"Job completed at {job.ended_at} with "
        f"status={job.get_status_display()}"
    )


def _job_create_update_cve(build: str, cve: CVERecord) -> CVE:
    instance: CVE
    try:
        instance = CVE.objects.get(cve=cve.id)

        instance_modified_at = (
            instance.modified_at
            if instance.modified_at
            else parse_datetime("0001-01-01T00:00Z")
        )
        cve_modified_at = (
            cve.modified_at
            if cve.modified_at
            else parse_datetime("0001-01-01T00:00Z")
        )

        if cve_modified_at > instance_modified_at:
            instance.details = cve.details
            instance.known_affected_software_configurations = (
                cve.known_affected_software_configurations
            )
            instance.impact = cve.impact
            instance.published_at = cve.published_at
            instance.modified_at = instance.modified_at
            instance.save()
    except CVE.DoesNotExist:
        instance = CVE.objects.create(
            cve=cve.id,
            details=cve.details,
            known_affected_software_configurations=(
                cve.known_affected_software_configurations
            ),
            impact=cve.impact,
            published_at=cve.published_at,
            modified_at=cve.modified_at,
        )

    return instance


def _job_create_local_file(build: str, cve: CVERecord) -> LocalFile:
    instance, _ = LocalFile.objects.get_or_create(local_file=cve.local_file)

    return instance


def _job_create_remote_file(build: str, cve: CVERecord) -> RemoteFile:
    instance, _ = RemoteFile.objects.get_or_create(remote_file=cve.remote_file)

    return instance


def _job_create_snippet(build: str, cve: CVERecord) -> Snippet:
    id_hash = hashlib.md5(
        json.dumps(cve.snippet, sort_keys=True).encode("utf-8")
    ).hexdigest()

    instance, _ = Snippet.objects.get_or_create(
        id=id_hash, snippet=cve.snippet
    )

    return instance


@app.task()
def job_process(build: str, fossid_records: List[Dict[str, Any]]) -> None:
    log = BuildLogAdapter(logger, {"build": build})

    _job_start(build)

    job: Job = Job.objects.get(build=build)
    status = Job.Status.FAILED
    message = None

    files = []
    for fossid_record in fossid_records:
        cve_record = CVERecord(build, fossid_record)

        if cve_record.type in ["ignored", "error", None]:
            log.debug(
                f"Skipped file {cve_record.local_file}, {cve_record.type}"
            )
            continue

        cve = _job_create_update_cve(build, cve_record)
        local_file = _job_create_local_file(build, cve_record)
        remote_file = _job_create_remote_file(build, cve_record)
        snippet = _job_create_snippet(build, cve_record)

        file, _ = File.objects.get_or_create(
            local_file=local_file,
            remote_file=remote_file,
            snippet=snippet,
            cve=cve,
        )
        files.append(file)
    else:
        job.files.add(*set(files))
        status = Job.Status.COMPLETED

    _job_complete(build, status, message)
