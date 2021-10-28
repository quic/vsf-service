# Copyright (c) 2021 Qualcomm Technologies, Inc.
# All Rights Reserved.
# Confidential and Proprietary - Qualcomm Technologies, Inc.
import hashlib
import io
import json
from unittest.mock import patch

import pandas as pd
from pandas.testing import assert_frame_equal
from rest_framework.test import APIClient, APITestCase

from service.models import CVE, File, Job, LocalFile, RemoteFile, Snippet


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

    @patch("service.views.job_process")
    def test_post_job_with_existing_build(self, job_process):
        client = APIClient()

        file = open("tests/data/test_input_data.fossid")

        response = client.post(
            "/jobs/",
            data={"build": "fake-image", "file": file},
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.data["error_message"],
            [
                "Job 1 has already been registered with build=fake-image with current status=Created"
            ],
        )

        job_process.assert_not_called()


class ReportViewsetTestCase(APITestCase):
    def setUp(self):
        self.cve = [
            CVE.objects.create(
                cve="CVE-2020-3615",
                details={
                    "data_type": "CVE",
                    "references": {
                        "reference_data": [
                            {
                                "url": "https://www.qualcomm.com/company/"
                                "product-security/bulletins/may-2020-bulletin",
                                "name": "https://www.qualcomm.com/company/"
                                "product-security/bulletins/may-2020-bulletin",
                                "tags": ["Patch", "Vendor Advisory"],
                                "refsource": "CONFIRM",
                            }
                        ]
                    },
                    "description": {
                        "description_data": [
                            {
                                "lang": "en",
                                "value": "Valid deauth/disassoc frames is dropped in case if RMF is enabled and some rouge peer keep on sending rogue deauth/disassoc frames due to improper enum values used to check the frame subtype in Snapdragon Auto, Snapdragon Compute, Snapdragon Consumer Electronics Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile in APQ8009, APQ8053, APQ8096AU, MDM9150, MDM9206, MDM9207C, MDM9607, MDM9650, MSM8996AU, QCA6174A, QCA6574AU, QCA9377, QCA9379, QCN7605, QCS605, SC8180X, SDM630, SDM636, SDM660, SDM845, SDX20, SDX24, SDX55, SM8150, SXR1130",  # noqa
                            }
                        ]
                    },
                },
                known_affected_software_configurations={
                    "nodes": [
                        {
                            "children": [
                                {
                                    "operator": "OR",
                                    "cpe_match": [
                                        {
                                            "cpe23Uri": "cpe:2.3:o:qualcomm:ap"
                                            "q8009_firmware:-:*:*:*:*:*:*:*",
                                            "vulnerable": True,
                                        }
                                    ],
                                },
                                {
                                    "operator": "OR",
                                    "cpe_match": [
                                        {
                                            "cpe23Uri": "cpe:2.3:h:qualcomm:"
                                            "apq8009:-:*:*:*:*:*:*:*",
                                            "vulnerable": False,
                                        }
                                    ],
                                },
                            ],
                            "operator": "AND",
                        }
                    ]
                },
                impact={
                    "baseMetricV2": {
                        "cvssV2": {
                            "version": "2.0",
                            "baseScore": 7.5,
                        },
                        "severity": "HIGH",
                    },
                    "baseMetricV3": {
                        "cvssV3": {
                            "scope": "UNCHANGED",
                            "version": "3.1",
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                        },
                        "impactScore": 5.9,
                    },
                },
                modified_at="2020-06-03 13:49:00+00",
                published_at="2020-06-02 15:15:00+00",
            ),
            CVE.objects.create(
                cve="CVE-2019-2041",
                details={
                    "data_type": "CVE",
                    "references": {
                        "reference_data": [
                            {
                                "url": "https://source.android.com/security/"
                                "bulletin/2019-04-01",
                                "name": "https://source.android.com/security/"
                                "bulletin/2019-04-01",
                                "tags": ["Patch", "Vendor Advisory"],
                                "refsource": "CONFIRM",
                            }
                        ]
                    },
                    "description": {
                        "description_data": [
                            {
                                "lang": "en",
                                "value": "In the configuration of NFC modules on certain devices, there is a possible failure to distinguish individual devices due to an insecure default value. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation. Product: Android. Versions: Android-8.1 Android-9. Android ID: A-122034690.",  # noqa
                            }
                        ]
                    },
                },
                known_affected_software_configurations={
                    "nodes": [
                        {
                            "operator": "OR",
                            "cpe_match": [
                                {
                                    "cpe23Uri": "cpe:2.3:o:google:android"
                                    ":8.1:*:*:*:*:*:*:*",
                                    "vulnerable": True,
                                },
                                {
                                    "cpe23Uri": "cpe:2.3:o:google:android"
                                    ":9.0:*:*:*:*:*:*:*",
                                    "vulnerable": True,
                                },
                            ],
                        }
                    ],
                    "CVE_data_version": "4.0",
                },
                impact={
                    "baseMetricV2": {
                        "cvssV2": {
                            "version": "2.0",
                            "baseScore": 6.9,
                        },
                        "severity": "MEDIUM",
                    },
                    "baseMetricV3": {
                        "cvssV3": {
                            "scope": "UNCHANGED",
                            "version": "3.0",
                            "baseScore": 7.3,
                            "baseSeverity": "HIGH",
                            "attackVector": "LOCAL",
                            "confidentialityImpact": "HIGH",
                        },
                        "impactScore": 5.9,
                        "exploitabilityScore": 1.3,
                    },
                },
                modified_at="2020-08-24 17:37:00+00",
                published_at="2019-04-19 20:29:00+00",
            ),
        ]

        self.local_files = [
            LocalFile.objects.create(
                local_file="/work/LA.UM.6.1.c25-11700-sdm660.1-1_uqtik22_/opensource/wlan/ol_txrx_types.h"
            ),
            LocalFile.objects.create(
                local_file="/work/LA.UM.6.1.c25-11700-sdm660.1-1_uqtik22_"
                "/opensource/external/libnfc-nci"
                "/libnfc-nxp_RF-PN553_example"
            ),
        ]

        self.remote_files = [
            RemoteFile.objects.create(
                remote_file={
                    "id": "3bf0e072ebb4836a63ac3b0d00000000",
                    "md5": "3bf0e072ebb4836a63ac3b0d00000000",
                    "path": "ol_txrx_types.h",
                    "size": 39279,
                    "encoding": "UTF-8",
                    "available": True,
                }
            ),
            RemoteFile.objects.create(
                remote_file={
                    "id": "987227e8e9a091959d4c072700000000",
                    "md5": "987227e8e9a091959d4c072700000000",
                    "path": "libnfc-nxp.blueline.conf",
                    "size": 12801,
                    "encoding": "UTF-8",
                    "available": True,
                }
            ),
            RemoteFile.objects.create(
                remote_file={
                    "id": "54bd14e1e17c205a7ee7b97100000000",
                    "md5": "54bd14e1e17c205a7ee7b97100000000",
                    "path": "libnfc-nxp.taimen.conf",
                    "size": 19846,
                    "encoding": "UTF-8",
                    "available": True,
                }
            ),
        ]
        self.snippet_ids_hashes = [
            hashlib.md5(
                json.dumps(
                    {
                        "id": "d23d5a5dc138f52e4c990c21c05e6258",
                        "local_size": 8,
                        "remote_size": 8,
                        "local_coverage": 0.01,
                    },
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest(),
            hashlib.md5(
                json.dumps(
                    {
                        "id": "9158f01f2eff351070cfdcecdbb995a2",
                        "local_size": 7,
                        "remote_size": 7,
                        "local_coverage": 0.09,
                    },
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest(),
        ]
        self.snippets = [
            Snippet.objects.create(
                id=self.snippet_ids_hashes[0],
                snippet={
                    "id": "d23d5a5dc138f52e4c990c21c05e6258",
                    "local_size": 8,
                    "remote_size": 8,
                    "local_coverage": 0.01,
                },
            ),
            Snippet.objects.create(
                id=self.snippet_ids_hashes[1],
                snippet={
                    "id": "9158f01f2eff351070cfdcecdbb995a2",
                    "local_size": 7,
                    "remote_size": 7,
                    "local_coverage": 0.09,
                },
            ),
        ]

        self.files = [
            File.objects.create(
                cve=self.cve[0],
                local_file=self.local_files[0],
                remote_file=self.remote_files[0],
                snippet=self.snippets[0],
            ),
            File.objects.create(
                cve=self.cve[1],
                local_file=self.local_files[1],
                remote_file=self.remote_files[1],
                snippet=self.snippets[1],
            ),
            File.objects.create(
                cve=self.cve[1],
                local_file=self.local_files[1],
                remote_file=self.remote_files[2],
                snippet=self.snippets[1],
            ),
        ]
        self.job = Job.objects.create(
            build="fake-image",
            created_at="2021-02-14T22:24:30.602597-08:00",
        )
        self.job.files.add(*set(self.files))

    def test_report(self):
        client = APIClient()

        response = client.get("/jobs/1/report/")

        excel_file_contents = io.BytesIO(response.content)

        actual_unique_df = pd.read_excel(
            excel_file_contents, engine="openpyxl", sheet_name="Unique"
        )
        actual_all_df = pd.read_excel(
            excel_file_contents, engine="openpyxl", sheet_name="All"
        )
        expected_unique_df = pd.read_excel(
            "tests/data/test_report.xlsx",
            engine="openpyxl",
            sheet_name="Unique",
        )
        expected_all_df = pd.read_excel(
            "tests/data/test_report.xlsx",
            engine="openpyxl",
            sheet_name="All",
        )

        assert_frame_equal(
            actual_unique_df,
            expected_unique_df,
            check_dtype=False,
            check_index_type=False,
        )
        assert_frame_equal(
            actual_all_df,
            expected_all_df,
            check_dtype=False,
            check_index_type=False,
        )

        self.assertEqual(
            response.get("Content-Disposition"),
            'attachment; filename="fake-image.xlsx"',
        )
        self.assertEqual(response.status_code, 200)

    def test_report_invalid_job_id(self):
        client = APIClient()

        response = client.get("/jobs/2/report/")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.data["detail"], "Not found.")
