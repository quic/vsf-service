"""
Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.

SPDX-License-Identifier: BSD-3-Clause
"""
import logging

from django.utils.dateparse import parse_datetime

logger = logging.getLogger(__name__)


class BuildLogAdapter(logging.LoggerAdapter):
    """
    Custom log adapter to prefix log messages with image name
    """

    def process(self, msg, kwargs):
        if self.extra.get("build"):
            processed_msg = f"[{self.extra.get('build')}] {msg}"
        else:
            processed_msg = f"{msg}"

        return processed_msg, kwargs


class CVERecord:
    def __init__(self, build: str, record: dict):
        self.record = record
        self.log = BuildLogAdapter(logger, {"build": build})

    @property
    def id(self):
        return self.record.get("vulnerability", {}).get("id")

    @property
    def type(self):
        return self.record.get("type")

    @property
    def details(self):
        return (
            self.record.get("vulnerability", {})
            .get("details", {})
            .get("cve", {})
        )

    @property
    def known_affected_software_configurations(self):
        return (
            self.record.get("vulnerability", {})
            .get("details", {})
            .get("configurations", {})
        )

    @property
    def impact(self):
        return (
            self.record.get("vulnerability", {})
            .get("details", {})
            .get("impact", {})
        )

    @property
    def remote_file(self):
        return self.record.get("file", {})

    @property
    def local_file(self):
        return self.record.get("local_path", None)

    @property
    def snippet(self):
        return self.record.get("snippet", {})

    @property
    def published_at(self):
        if published_at := (
            self.record.get("vulnerability", {})
            .get("details", {})
            .get("publishedDate")
        ):
            published_at = parse_datetime(published_at)

        return published_at

        # return parse_datetime(
        #     self.record.get("vulnerability", {})
        #     .get("details", {})
        #     .get("publishedDate")
        # )

    @property
    def modified_at(self):
        if modified_at := (
            self.record.get("vulnerability", {})
            .get("details", {})
            .get("lastModifiedDate")
        ):
            modified_at = parse_datetime(modified_at)

        return modified_at

        # return parse_datetime(
        #     self.record.get("vulnerability", {})
        #     .get("details", {})
        #     .get("lastModifiedDate")
        # )
