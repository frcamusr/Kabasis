# Generated by Django 3.2.22 on 2024-01-25 21:02

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('CursosApp', '0023_auto_20231212_1204'),
    ]

    operations = [
        migrations.AddField(
            model_name='video',
            name='archivo_video',
            field=models.FileField(blank=True, null=True, upload_to='videos/', validators=[django.core.validators.FileExtensionValidator(allowed_extensions=['mp4'])]),
        ),
    ]