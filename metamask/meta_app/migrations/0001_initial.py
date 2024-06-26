# Generated by Django 5.0.6 on 2024-06-02 06:02

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('Authentication', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='ChainDetails',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('network_name', models.CharField(max_length=255, unique=True)),
                ('chain_name', models.CharField(max_length=255, unique=True)),
                ('chain_rpc', models.CharField(max_length=1000, unique=True)),
                ('chain_symbol', models.CharField(max_length=100, unique=True)),
                ('chain_logo', models.ImageField(upload_to='media')),
            ],
        ),
        migrations.CreateModel(
            name='EthereumAccount',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('chain_symbol', models.CharField(max_length=100, unique=True)),
                ('address', models.CharField(max_length=100)),
                ('private_key', models.CharField(max_length=100)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='Authentication.customuser')),
            ],
        ),
        migrations.CreateModel(
            name='TokenContract',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('address', models.CharField(max_length=42, unique=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='Authentication.customuser')),
            ],
        ),
    ]
