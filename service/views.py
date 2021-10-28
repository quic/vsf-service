"""
Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.

SPDX-License-Identifier: BSD-3-Clause
"""
import logging
import pandas as pd

from io import BytesIO

from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from rest_framework import mixins, status, viewsets
from rest_framework.response import Response

from service.models import (
    CVE_VALUE,
    CVSS_V2_BASE_SCORE,
    CVSS_V2_SEVERITY,
    CVSS_V3_BASE_SCORE,
    CVSS_V3_SEVERITY,
    DESCRIPTION,
    LOCAL_FILE,
    MODIFIED_AT,
    PACKAGE_FOUND,
    PUBLISHED_AT,
    REMOTE_FILE,
    REMOTE_FILE_ID,
    SID,
    Job,
)
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


class JobReportViewSet(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    """
    ### read
    #### GET `jobs/{job_id}/reports/`
    Generates and returns the VSF excel file.

    #### Path Parameters
    * `job_id` *required* A unique integer value identifying the job.
    """

    def list(self, request, *args, **kwargs):
        job_id = kwargs.get("job_id")
        job = get_object_or_404(Job, pk=job_id)
        data = job.files.all()
        filename = f"{job.build}.xlsx"

        if not data:
            return _prepare_bad_request_response(
                f"No record found with Job ID {job_id}."
            )

        dataset = self._prepare_dataset(data)
        unique_dataset = self._prepare_unique_cves_dataset(dataset)
        all_dataset = dataset[
            [
                CVE_VALUE,
                SID,
                CVSS_V2_SEVERITY,
                CVSS_V2_BASE_SCORE,
                CVSS_V3_SEVERITY,
                CVSS_V3_BASE_SCORE,
                DESCRIPTION,
                PUBLISHED_AT,
                MODIFIED_AT,
                REMOTE_FILE,
                REMOTE_FILE_ID,
                LOCAL_FILE,
            ]
        ].copy()

        # Excel does not understand datetime with timezone, therefore
        # converting the columns to str
        # Error got while creating excel via 'to_excel()':
        # ValueError: Excel does not support datetimes with timezones.
        # Please ensure that datetimes are timezone unaware before
        # writing to Excel.
        unique_dataset[PUBLISHED_AT] = (
            unique_dataset[PUBLISHED_AT].astype(str).str[:-6]
        )
        all_dataset[PUBLISHED_AT] = (
            all_dataset[PUBLISHED_AT].astype(str).str[:-6]
        )
        all_dataset[MODIFIED_AT] = (
            all_dataset[MODIFIED_AT].astype(str).str[:-6]
        )

        report = BytesIO()

        with pd.ExcelWriter(
            report,
            engine="xlsxwriter",
            engine_kwargs={"options": {"strings_to_urls": False}},
        ) as writer:
            unique_dataset.to_excel(
                writer,
                sheet_name="Unique",
                index=False,
            )
            all_dataset.to_excel(
                writer,
                sheet_name="All",
                index=False,
            )

            # Formatting the worksheet
            # Declare the workbook
            workbook = writer.book

            unique_cve_worksheet = writer.sheets["Unique"]
            all_cve_worksheet = writer.sheets["All"]

            # Add font format.
            link_format = workbook.add_format(
                {
                    "font_name": "Calibri",
                    "font_size": "11",
                    "bold": False,
                    "valign": "vcenter",
                    "underline": 1,
                    "font_color": "blue",
                    "text_wrap": True,
                }
            )
            header_format = workbook.add_format(
                {
                    "bold": True,
                    "center_across": True,
                    "fg_color": "#B0D3F0",
                    "border": 1,
                }
            )
            # add cve url hyperlinked to cve number
            unique_dataset.apply(
                lambda row: unique_cve_worksheet.write_url(
                    row.name + 1,
                    0,
                    url=f"{settings.CVE_URL}{row[CVE_VALUE]}",
                    string=row[CVE_VALUE],
                    cell_format=link_format,
                ),
                axis=1,
            )
            all_dataset.apply(
                lambda row: all_cve_worksheet.write_url(
                    row.name + 1,
                    0,
                    url=f"{settings.CVE_URL}{row[CVE_VALUE]}",
                    string=row[CVE_VALUE],
                ),
                axis=1,
            )

            # formatting header in sheets
            for col_num, value in enumerate(unique_dataset.columns):
                unique_cve_worksheet.write(0, col_num, value, header_format)
            for col_num, value in enumerate(all_dataset.columns):
                all_cve_worksheet.write(0, col_num, value, header_format)

            unique_cve_worksheet.set_zoom(80)
            unique_cve_worksheet.set_column("A:E", 18)
            unique_cve_worksheet.set_column("F:F", 30)
            unique_cve_worksheet.set_column("G:G", 55)
            unique_cve_worksheet.set_column("H:H", 22)

            all_cve_worksheet.set_column("A:F", 17)
            all_cve_worksheet.set_column("G:G", 55)
            all_cve_worksheet.set_column("H:J", 22)
            all_cve_worksheet.set_column("K:K", 30)
            all_cve_worksheet.set_column("L:L", 8)
            all_cve_worksheet.set_column("M:M", 55)
            all_cve_worksheet.set_column("N:N", 15)
            all_cve_worksheet.set_column(
                "B:B", None, None, {"hidden": True}
            )  # Hiding column B
            all_cve_worksheet.set_zoom(
                80
            )  # Setting worksheet zoom level to 80%

        report.seek(0)

        response = HttpResponse(
            report.read(),
            content_type=(
                "application/"
                "vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            ),
            status=200,
        )
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response

    def _prepare_dataset(self, data):
        """
        Prepares the dataset required for CVE report.

        Args:
            data: CVE/File details.

        Returns:
            Dataframe containing required fields for generating report.
        """
        dataset = []
        for item in data:
            dataset.append(
                {
                    CVE_VALUE: item.cve.cve,
                    CVSS_V2_BASE_SCORE: item.cvss_v2_base_score,
                    CVSS_V2_SEVERITY: item.cvss_v2_severity,
                    CVSS_V3_BASE_SCORE: item.cvss_v3_base_score,
                    CVSS_V3_SEVERITY: item.cvss_v3_severity,
                    DESCRIPTION: item.description,
                    LOCAL_FILE: item.local_file.local_file,
                    MODIFIED_AT: item.modified_at,
                    PACKAGE_FOUND: item.package_found,
                    PUBLISHED_AT: item.published_at,
                    REMOTE_FILE_ID: item.remote_id,
                    REMOTE_FILE: item.remote_file_path,
                    SID: item.sid,
                }
            )

        return pd.DataFrame(dataset)

    def _prepare_unique_cves_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Group the data frame as per unique CVE, and append some meta data
        fields.

        Args:
            df: Dataframe containing CVE Details.

        Returns:
            Dataframe with unique CVE records.
        """
        unique_sheet = (
            df.groupby(CVE_VALUE)
            .agg(
                {
                    CVSS_V2_SEVERITY: "first",
                    CVSS_V2_BASE_SCORE: "first",
                    CVSS_V3_SEVERITY: "first",
                    CVSS_V3_BASE_SCORE: "first",
                    PACKAGE_FOUND: "first",
                    DESCRIPTION: "first",
                    PUBLISHED_AT: "first",
                }
            )
            .sort_values(CVE_VALUE, ascending=False)
            .reset_index()
        )

        return unique_sheet


def _prepare_bad_request_response(message: str) -> Response:
    return Response(
        {"result": False, "message": message},
        status=status.HTTP_400_BAD_REQUEST,
    )
