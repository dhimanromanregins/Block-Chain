# Generated by Django 5.0.6 on 2024-06-02 06:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('meta_app', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Transaction_hash',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('transaction_hash', models.CharField(max_length=1000)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]