# Generated by Django 4.2.6 on 2023-11-22 03:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('CursosApp', '0016_remove_questioncontent_curso_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='curso',
            name='orden',
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
    ]