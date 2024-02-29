# Generated by Django 4.2.9 on 2024-01-29 20:07

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("weblate_auth", "0002_squashed_weblate_5"),
    ]

    operations = [
        migrations.CreateModel(
            name="OwaVerification",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("token", models.CharField(max_length=32)),
                ("remote_url", models.TextField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={
                "indexes": [
                    models.Index(fields=["token"], name="weblate_aut_token_9d3c96_idx")
                ],
            },
        ),
    ]
