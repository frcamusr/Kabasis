# Generated by Django 3.2.22 on 2024-02-06 17:51

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('AutenticacionApp', '0030_auto_20240201_1452'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='empresa',
            name='areas',
        ),
    ]
