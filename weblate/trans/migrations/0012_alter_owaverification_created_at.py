# Generated by Django 4.2.9 on 2024-01-30 10:41

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("trans", "0011_owaverification"),
    ]

    operations = [
        migrations.AlterField(
            model_name="owaverification",
            name="created_at",
            field=models.DateTimeField(auto_now_add=True),
        ),
    ]
