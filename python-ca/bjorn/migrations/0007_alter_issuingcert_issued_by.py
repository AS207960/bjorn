# Generated by Django 3.2.6 on 2021-09-02 13:16

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('bjorn', '0006_issuingcert_name'),
    ]

    operations = [
        migrations.AlterField(
            model_name='issuingcert',
            name='issued_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='certificates', to='bjorn.issuingcert'),
        ),
    ]
