# Generated by Django 4.2.6 on 2023-11-20 15:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('CursosApp', '0009_remove_curso_aprobado_remove_curso_orden'),
    ]

    operations = [
        migrations.AddField(
            model_name='quizcontent',
            name='orden',
            field=models.PositiveIntegerField(default=1),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='video',
            name='orden',
            field=models.PositiveIntegerField(default=2),
            preserve_default=False,
        ),
    ]
