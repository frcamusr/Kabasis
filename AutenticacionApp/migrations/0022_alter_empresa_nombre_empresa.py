# Generated by Django 3.2.22 on 2024-01-16 14:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('AutenticacionApp', '0021_alter_empresa_nombre_empresa'),
    ]

    operations = [
        migrations.AlterField(
            model_name='empresa',
            name='nombre_empresa',
            field=models.CharField(max_length=50, unique=True),
        ),
    ]