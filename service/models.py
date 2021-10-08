"""
Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.

SPDX-License-Identifier: BSD-3-Clause
"""
from django.db import models
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from service.utils import build_package_information


CVE_VALUE = "CVE"
CVSS_V2_BASE_SCORE = "CVSS V2 Base Score"
CVSS_V2_SEVERITY = "CVSS V2 Severity"
CVSS_V3_BASE_SCORE = "CVSS V3 Base Score"
CVSS_V3_SEVERITY = "CVSS V3 Severity"
DESCRIPTION = "Description"
LOCAL_FILE = "Local File"
MODIFIED_AT = "Modified At"
PACKAGE_FOUND = "Package Found"
PUBLISHED_AT = "Published At"
REMOTE_FILE = "Remote File"
REMOTE_FILE_ID = "Remote File ID"
SID = "SID"


class LocalFile(models.Model):
    local_file = models.TextField(unique=True)

    class Meta:
        db_table = "local_files"


class RemoteFile(models.Model):
    remote_file = models.JSONField(unique=True)

    class Meta:
        db_table = "remote_files"


class Snippet(models.Model):
    id = models.UUIDField(primary_key=True)
    snippet = models.JSONField(blank=False, null=False)

    class Meta:
        db_table = "snippets"


class CVE(models.Model):
    cve = models.TextField(primary_key=True)
    details = models.JSONField(blank=True, null=True)
    known_affected_software_configurations = models.JSONField(
        blank=True, null=True
    )
    impact = models.JSONField(blank=True, null=True)
    published_at = models.DateTimeField(blank=True, null=True)
    modified_at = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return (
            f"{self.__class__.__name__}"
            f"({self.cve}, ..., {self.published_at}, {self.modified_at})"
        )

    class Meta:
        db_table = "cves"


class File(models.Model):
    local_file = models.ForeignKey(LocalFile, on_delete=models.PROTECT)
    remote_file = models.ForeignKey(RemoteFile, on_delete=models.PROTECT)
    snippet = models.ForeignKey(Snippet, on_delete=models.PROTECT)
    cve = models.ForeignKey(CVE, on_delete=models.PROTECT)

    class Meta:
        db_table = "files"
        constraints = [
            models.UniqueConstraint(
                fields=["local_file", "remote_file", "snippet", "cve"],
                name="file_fields_all_uniq_key",
            )
        ]

    @property
    def cvss_v2_base_score(self):
        return (
            self.cve.impact.get("baseMetricV2", {})
            .get("cvssV2", {})
            .get("baseScore", "")
        )

    @property
    def cvss_v2_severity(self):
        return self.cve.impact.get("baseMetricV2", {}).get("severity")

    @property
    def cvss_v3_base_score(self):
        return (
            self.cve.impact.get("baseMetricV3", {})
            .get("cvssV3", {})
            .get("baseScore", "")
        )

    @property
    def cvss_v3_severity(self):
        return (
            self.cve.impact.get("baseMetricV3", {})
            .get("cvssV3", {})
            .get("baseSeverity", "")
        )

    @property
    def description(self):
        try:
            cve_description = (
                self.cve.details.get("cve", {})
                if self.cve.details.get("cve", {})
                else self.cve.details.get("description", {})
            )
            description = cve_description.get("description_data", [])[0].get(
                "value"
            )
        except IndexError:
            description = None

        return description

    @property
    def modified_at(self):
        return self.cve.modified_at

    @property
    def package_found(self):
        try:
            return build_package_information(
                self.cve.known_affected_software_configurations
            )
        except Exception:
            return None

    @property
    def published_at(self):
        return self.cve.published_at

    @property
    def remote_id(self):
        return self.remote_file.remote_file.get("id")

    @property
    def remote_file_path(self):
        return self.remote_file.remote_file.get("path")

    @property
    def sid(self):
        return self.snippet.snippet.get("id")


class Job(models.Model):
    class Status(models.IntegerChoices):
        CREATED = 0, _("Created")
        STARTED = 1, _("Started")
        COMPLETED = 2, _("Completed")
        FAILED = 3, _("Failed")

    build = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(blank=True, null=True)
    ended_at = models.DateTimeField(blank=True, null=True)
    status = models.PositiveSmallIntegerField(
        choices=Status.choices, default=Status.CREATED
    )
    message = models.TextField(blank=True, null=True)
    files = models.ManyToManyField(File, related_name="jobs")

    def get_absolute_url(self):
        return reverse("job-detail", kwargs={"pk": self.pk})

    class Meta:
        db_table = "jobs"
        ordering = ("-id",)
