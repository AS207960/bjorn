# Generated by Django 3.2.6 on 2021-09-08 17:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('bjorn', '0011_authorizationchallenge'),
    ]

    operations = [
        migrations.AlterField(
            model_name='authorizationchallenge',
            name='processing',
            field=models.BooleanField(blank=True, default=True),
        ),
    ]
