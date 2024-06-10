from django.db import models
from Authentication.models import CustomUser
from django.core.exceptions import ValidationError
import uuid

# Create your models here.


class ChainDetails(models.Model):
    network_name = models.CharField(max_length=255, unique=True)
    chain_name = models.CharField(max_length=255, unique=True)
    chain_rpc = models.CharField(max_length=1000, unique=True)
    chain_symbol = models.CharField(max_length=100, unique=True)
    chain_logo = models.ImageField(upload_to="media")
    def __str__(self):
        return self.chain_name

class EthereumAccount(models.Model):
    chain_symbol = models.CharField(max_length=100, unique=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    address = models.CharField(max_length=100)
    private_key = models.CharField(max_length=100)

    def __str__(self):
        return self.user.username


class TokenContract(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    address = models.CharField(max_length=42, unique=True)

    def __str__(self):
        return self.user.username


class Transaction_hash(models.Model):
    transaction_hash = models.CharField(max_length=1000)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.transaction_hash


class Coin_Details(models.Model):
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name

class Binance(models.Model):
    coin = models.ForeignKey(Coin_Details, on_delete=models.CASCADE)
    api_key = models.CharField(max_length=1000)
    token_address = models.CharField(max_length=1000)

    def __str__(self):
        return self.coin



class SspWallet(models.Model):
    ssp_wallet = models.CharField(max_length=1000)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = models.Manager()

    def save(self, *args, **kwargs):
        if not self.pk and SspWallet.objects.exists():
            raise ValidationError('Only one SspWallet instance is allowed.')
        super(SspWallet, self).save(*args, **kwargs)

    def __str__(self):
        return self.ssp_wallet


class RePayment(models.Model):
    re_pay_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    total_amount = models.CharField(max_length=1000)
    un_paid_amount = models.CharField(max_length=1000)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ssp_wallet

