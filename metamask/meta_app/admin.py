# admin.py
from django.contrib import admin
from .models import EthereumAccount,ChainDetails, PaymentDetails,Transaction_hash,Coin_Details, Binance

@admin.register(EthereumAccount)
class EthereumAccountAdmin(admin.ModelAdmin):
    list_display = ('user', 'address', 'private_key')


admin.site.register(ChainDetails)
admin.site.register(Transaction_hash)
admin.site.register(Coin_Details)
admin.site.register(Binance)
admin.site.register(PaymentDetails)