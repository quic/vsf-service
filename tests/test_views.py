# Copyright (c) 2021 Qualcomm Technologies, Inc.
# All Rights Reserved.
# Confidential and Proprietary - Qualcomm Technologies, Inc.
import json
from unittest.mock import patch

from rest_framework.test import APIClient, APITestCase

from service.models import Job


class JobViewSetTestCase(APITestCase):
    def setUp(self) -> None:
        self.job = Job.objects.create(build="fake-image")

    def test_get_jobs(self):
        client = APIClient()
        response = client.get("/jobs/")

        self.assertEqual(response.status_code, 200)

        result = dict(response.data[0])
        self.assertEqual(result["id"], 1)
        self.assertEqual(result["build"], "fake-image")
        self.assertEqual(result["status"], "Created")
        self.assertIsNone(result["message"])
        self.assertIsNotNone(result["created_at"])
        self.assertIsNone(result["started_at"])
        self.assertIsNone(result["ended_at"])

    def test_get_jobs_by_id(self):
        client = APIClient()
        response = client.get("/jobs/1/")

        self.assertEqual(response.status_code, 200)

        result = response.data
        self.assertEqual(result["id"], 1)
        self.assertEqual(result["build"], "fake-image")

    @patch("service.views.job_process")
    def test_post_job(self, job_process):
        client = APIClient()

        file = open("tests/data/test_input_data.fossid")

        response = client.post(
            "/jobs/",
            data={"build": "fake-image-1", "file": file},
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["id"], 2)
        self.assertEqual(response.data["build"], "fake-image-1")
        self.assertIsNotNone(response.data["created_at"])
        self.assertIsNone(response.data["started_at"])
        self.assertIsNone(response.data["ended_at"])
        self.assertEqual(response.data["status"], "Created")
        self.assertIsNone(response.data["message"])

        job_process.apply_async(args=[2, ""])

    @patch("service.views.job_process")
    def test_post_job_invalid(self, job_process):
        client = APIClient()

        file = open("tests/data/test_invalid_file.txt")

        response = client.post(
            "/jobs/",
            data={"build": "fake-image-1", "file": file},
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.data["file"],
            ["test_invalid_file.txt is not valid fossid output file."],
        )

        job_process.assert_not_called()
