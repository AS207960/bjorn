# Generated by Django 3.2.6 on 2021-08-30 12:04

import bjorn.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('bjorn', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='accountkey',
            name='secret',
            field=models.BinaryField(default=bjorn.models.make_account_key),
        ),
    ]
