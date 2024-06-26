# urls.py
from django.urls import path
from .views import *
from django.conf import settings
from django.conf.urls.static import static
urlpatterns = [
    path('generate-ethereum-account/', GenerateNetworkAccount.as_view(), name='generate-coin-account'),
    path('ethereum-balance/<str:address>/<str:symbol>', CoinBalance.as_view(), name='coin-balance'),
    path('coin-transaction-history/<str:address>/', CoinTransactionHistory.as_view(), name='coin-transaction-history'),
    path('token_info/<str:address>/', CoinTokenInfo.as_view(), name='token-info'),
    path('coin_price/', CoinPriceView.as_view(), name='coin_price'),
    path('send_crypto/', SendCoinView.as_view(), name='send_coin'),
    path('generate-qr/', EthereumQRCodeAPIView.as_view(), name='generate_qr'),
    path('balance/<str:address>/<str:symbol>/', CoinBalance.as_view(), name='coin_balance'),
    path('paymentbinance/', PaymentBinanceAPIView.as_view(), name='paymentbinance'),
    path('payment/', PaymentAPIView.as_view(), name='payment'),
    path('re_payment/<str:re_pay_id>/', RePaymentDetail.as_view(), name='re_payment_detail'),
    path('re_payment/', RePaymentDetail.as_view(), name='re_payment_create'),
    path('paymentdetails/<str:api_key>/', PaymentDetailsList.as_view(), name='paymentdetails-list'),
    path('paymentdetails/', PaymentDetailsList.as_view(), name='paymentdetails-post'),
]
