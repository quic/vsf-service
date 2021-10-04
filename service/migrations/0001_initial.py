"""
Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.

SPDX-License-Identifier: BSD-3-Clause
"""
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="CVE",
            fields=[
                ("cve", models.TextField(primary_key=True, serialize=False)),
                ("details", models.JSONField(blank=True, null=True)),
                (
                    "known_affected_software_configurations",
                    models.JSONField(blank=True, null=True),
                ),
                ("impact", models.JSONField(blank=True, null=True)),
                ("published_at", models.DateTimeField(blank=True, null=True)),
                ("modified_at", models.DateTimeField(blank=True, null=True)),
            ],
            options={
                "db_table": "cves",
            },
        ),
        migrations.CreateModel(
            name="LocalFile",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("local_file", models.TextField(unique=True)),
            ],
            options={
                "db_table": "local_files",
            },
        ),
        migrations.CreateModel(
            name="RemoteFile",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("remote_file", models.JSONField(unique=True)),
            ],
            options={
                "db_table": "remote_files",
            },
        ),
        migrations.CreateModel(
            name="Snippet",
            fields=[
                ("id", models.UUIDField(primary_key=True, serialize=False)),
                ("snippet", models.JSONField()),
            ],
            options={
                "db_table": "snippets",
            },
        ),
        migrations.CreateModel(
            name="File",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "cve",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        to="service.cve",
                    ),
                ),
                (
                    "local_file",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        to="service.localfile",
                    ),
                ),
                (
                    "remote_file",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        to="service.remotefile",
                    ),
                ),
                (
                    "snippet",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        to="service.snippet",
                    ),
                ),
            ],
            options={
                "db_table": "files",
            },
        ),
        migrations.CreateModel(
            name="Job",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("build", models.CharField(max_length=100)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("ended_at", models.DateTimeField(blank=True, null=True)),
                (
                    "status",
                    models.PositiveSmallIntegerField(
                        choices=[
                            (0, "Created"),
                            (1, "Started"),
                            (2, "Completed"),
                            (3, "Failed"),
                        ],
                        default=0,
                    ),
                ),
                ("message", models.TextField(blank=True, null=True)),
                ("files", models.ManyToManyField(to="service.File")),
            ],
            options={
                "db_table": "jobs",
                "ordering": ("-id",),
            },
        ),
        migrations.AddConstraint(
            model_name="file",
            constraint=models.UniqueConstraint(
                fields=("local_file", "remote_file", "snippet", "cve"),
                name="file_fields_all_uniq_key",
            ),
        ),
    ]
