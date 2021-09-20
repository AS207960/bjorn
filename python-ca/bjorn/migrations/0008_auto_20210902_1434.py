# Generated by Django 3.2.6 on 2021-09-02 14:34

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('bjorn', '0007_alter_issuingcert_issued_by'),
    ]

    operations = [
        migrations.AddField(
            model_name='issuingcert',
            name='cert_url',
            field=models.URLField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='issuingcert',
            name='crl_url',
            field=models.URLField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='issuingcert',
            name='ocsp_responder_url',
            field=models.URLField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='orderauthorization',
            name='authorization',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='orders', to='bjorn.authorization'),
        ),
    ]
