# Generated by Django 5.0.6 on 2024-06-02 06:05

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('Authentication', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='encrypteddata',
            old_name='clientId',
            new_name='iv',
        ),
    ]
