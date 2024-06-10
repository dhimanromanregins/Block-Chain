# serializers.py
from rest_framework import serializers
from .models import EthereumAccount , TokenContract,ChainDetails, RePayment

class EthereumAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = EthereumAccount
        fields = ('user', 'address', 'private_key')


class TokenContractSerializer(serializers.ModelSerializer):
    class Meta:
        model = TokenContract
        fields = ['user','address']


class TokenInfoSerializer(serializers.Serializer):
    token_contract_address = serializers.CharField()
    balance = serializers.IntegerField()
    name = serializers.CharField()
    symbol = serializers.CharField()


class EthPriceSerializer(serializers.Serializer):
    ethereum_inr = serializers.FloatField()

class ChainDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChainDetails
        fields = '__all__'

class RePaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = RePayment
        fields = ['re_pay_id', 'total_amount', 'un_paid_amount', 'created_at']
        read_only_fields = ['re_pay_id', 'created_at']