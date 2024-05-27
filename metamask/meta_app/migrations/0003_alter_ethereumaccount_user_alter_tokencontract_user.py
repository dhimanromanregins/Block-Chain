# Generated by Django 4.2.13 on 2024-05-27 09:23

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('Authentication', '0003_encrypteddata'),
        ('meta_app', '0002_rename_chain_chaindetails_network_name'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ethereumaccount',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='Authentication.customuser'),
        ),
        migrations.AlterField(
            model_name='tokencontract',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='Authentication.customuser'),
        ),
    ]
