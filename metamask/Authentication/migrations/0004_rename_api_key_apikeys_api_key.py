# Generated by Django 4.2.13 on 2024-06-10 09:48

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('Authentication', '0003_remove_apikeys_api_key_apikeys_api_key'),
    ]

    operations = [
        migrations.RenameField(
            model_name='apikeys',
            old_name='api_key',
            new_name='Api_key',
        ),
    ]
