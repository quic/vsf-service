"""
Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.

SPDX-License-Identifier: BSD-3-Clause
"""
from django.db import models
from django.urls import reverse
from django.utils.translation import gettext_lazy as _


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
