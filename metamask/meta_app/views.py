# views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from django.conf import settings
from .models import EthereumAccount, TokenContract, ChainDetails, Transaction_hash,Binance, Coin_Details, SspWallet
from .serializers import EthereumAccountSerializer,TokenInfoSerializer,ChainDetailsSerializer
from web3 import Web3, Account
import requests
from .utils import get_token_logo_path, send_usdt
from Authentication.models import CustomUser, EncryptedData
from Authentication.utils import  encrypt, decrypt, pad
import binascii
from rest_framework import status as rest_status
from Crypto.Random import get_random_bytes
import json
import pyqrcode
import os
from rest_framework import status
import datetime
import base64



class GenerateNetworkAccount(APIView):
    def post(self, request):
        user_name = request.data.get('user_name')
        chain_symbol = request.data.get('chain_symbol', 'SSP')

        if user_name is None:
            return Response({"message": "user_name is required in the request data."},
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(username=user_name)
        except CustomUser.DoesNotExist:
            return Response({"message": "User not found."},
                            status=status.HTTP_404_NOT_FOUND)

        chain_details = ChainDetails.objects.all()
        chain_details_serializer = ChainDetailsSerializer(chain_details, many=True)

        user_chain_account = EthereumAccount.objects.filter(user=user, chain_symbol=chain_symbol).first()
        if user_chain_account:
            return Response({
                "message": f"User Address already exists for chain_symbol {chain_symbol}",
                "address": user_chain_account.address,
                "Chains": chain_details_serializer.data,
                "Status": status.HTTP_409_CONFLICT
            }, status=status.HTTP_409_CONFLICT)

        rpc = ChainDetails.objects.filter(chain_symbol=chain_symbol).first()
        rpc_url = rpc.chain_rpc

        w3 = Web3(Web3.HTTPProvider(rpc_url))

        account = Account.create()
        private_key = account.key
        address = account.address

        try:
            ethereum_account = EthereumAccount.objects.create(
                user=user,
                chain_symbol=chain_symbol,
                address=address,
                private_key=private_key.hex()
            )
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        ethereum_account_serializer = EthereumAccountSerializer(ethereum_account)

        response_data = {
            "User_data": ethereum_account_serializer.data,
            "Chains": chain_details_serializer.data
        }

        return Response(response_data, status=status.HTTP_201_CREATED)





class CoinTransactionHistory(APIView):
    def get(self, request, address):
        # Replace with your Etherscan API key
        api_key = "7DI9U879W1P9613SHPVUEKMXF7WDT85D5X"

        # Etherscan API endpoint for getting the transaction list
        api_url = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&sort=desc&apikey={api_key}"
        print(api_url, '==========')

        try:
            response = requests.get(api_url)
            if response.status_code == 200:
                data = response.json()
                if data["status"] == "1":
                    transactions = data["result"]
                    return Response(transactions, status=status.HTTP_200_OK)
                else:
                    return Response({"message": "Etherscan API response status is not '1'."}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"message": "Failed to connect to Etherscan API."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class CoinTokenInfo(APIView):
    def get(self, request, address):
        # Initialize a web3.py instance
        w3 = Web3(Web3.HTTPProvider('https://bsc-dataseed.binance.org/'))

        # Define the contract address and ABI of the token
        token_contract_address = '0x55d398326f99059fF775485246999027B3197955'
        token_abi_url = f'https://api.bscscan.com/api?module=contract&action=getabi&address={token_contract_address}'

        # Fetch the ABI from BSCScan
        response = requests.get(token_abi_url)
        token_abi = response.json()['result']

        # Create a contract instance
        token_contract = w3.eth.contract(address=token_contract_address, abi=token_abi)

        # Function to get token balance
        def get_token_balance(address):
            balance = token_contract.functions.balanceOf(address).call()
            return balance

        # Function to get token name and symbol
        def get_token_info():
            token_name = token_contract.functions.name().call()
            token_symbol = token_contract.functions.symbol().call()
            return token_name, token_symbol

        # Function to get token logo path (you need to define this function)
        def get_token_logo_path(contract_address):
            # Implement this function to get the logo path
            pass

        try:
            token_balance = get_token_balance(address)
            token_name, token_symbol = get_token_info()
            logo = get_token_logo_path(token_contract_address)
            data = {
                'address': address,
                'token_balance': token_balance,
                'token_name': token_name,
                'token_symbol': token_symbol,
                'token_logo': logo
            }
            return Response(data)
        except Exception as e:
            return Response({'error': str(e)})


class CoinPriceView(APIView):
    def get(self, request):
        crypto_name = request.query_params.get('crypto_name')
        currency = request.query_params.get('currency', 'usd')
        amount = request.query_params.get('amount')

        amount = float(amount)

        if crypto_name is None:
            return Response({"message": "crypto_name is required in the request data."}, status=status.HTTP_400_BAD_REQUEST)
        if amount is None:
            return Response({"message": "amount is required in the request data."}, status=status.HTTP_400_BAD_REQUEST)
        eth_price_url = 'https://api.coingecko.com/api/v3/simple/price'
        params = {
            'ids': crypto_name,
            'vs_currencies': currency,
        }

        try:
            response = requests.get(eth_price_url, params=params)
            data = response.json()
            token_price = data.get(crypto_name, {}).get(currency)

            if token_price is not None:
                try:
                    # Convert token_price and amount to float, then calculate the USD price
                    token_price = float(token_price)
                    amount = float(amount)
                    usd_price = token_price * amount
                    return Response({f'{crypto_name}_{currency}': usd_price})
                except ValueError:
                    return Response({'error': 'Invalid numeric value for token_price or amount.'}, status=400)
            else:
                return Response({'error': f'Token price data not found for {crypto_name} in {currency} in the response.'}, status=400)
        except Exception as e:
            return Response({'error': str(e)}, status=500)


class SendCoinView(APIView):
    def post(self, request):
        try:
            data = request.data
            sender_address = data.get('sender_address')
            receiver_address = data.get('receiver_address')
            value = data.get('value')
            print(request.data)
            if not sender_address or not receiver_address or value is None:
                return Response({'error': 'sender_address, receiver_address, and value must be provided in the request body'}, status=400)

            # Connect to an Ethereum node
            w3 = Web3(Web3.HTTPProvider('https://fittest-misty-seed.quiknode.pro/0a037be47a682e693c5de2a0698134eefa60928b/'))

            # Check if the sender has a sufficient balance for the transfer
            sender_balance = w3.eth.get_balance(sender_address)
            print(type(sender_balance), '============')
            print(type(value))
            if sender_balance <= value:
                return Response({'error': 'Insufficient balance in sender_address'}, status=400)

            # Create and send the transaction
            tx_hash = w3.eth.send_transaction({
                "from": sender_address,
                "to": receiver_address,
                "value": w3.to_wei(int(value), 'ether'),
            })

            return Response({'tx_hash': tx_hash}, status=200)

        except Exception as e:
            return Response({'error': str(e)}, status=500)


class EthereumQRCodeAPIView(APIView):
    def post(self, request):
        wallet_address = request.data.get('wallet_address')
        amount = request.data.get('amount', 0)
        data = f'ethereum:{wallet_address}?value={amount}'
        qr = pyqrcode.create(data)
        qr_file_path = os.path.join(settings.MEDIA_ROOT, "ethereum_qrcode.svg")
        qr.svg(qr_file_path, scale=8)
        qr_url = request.build_absolute_uri(settings.MEDIA_URL + "ethereum_qrcode.svg")
        data = {
            'message': 'Ethereum QR code generated successfully',
            'qr_code_url': qr_url,
            'wallet_address': wallet_address,
            'qr_file_path': qr_file_path
        }
        return Response(data, status=status.HTTP_201_CREATED)

def Wei_to_Eth(amount):
    amount_is_wei = amount
    wei_to_ether_conversion_factor = 10 ** 18
    value_in_ether = amount_is_wei / wei_to_ether_conversion_factor
    return value_in_ether


def get_eth_to_usd_exchange_rate():
    try:
        url = 'https://api.coingecko.com/api/v3/simple/price?ids=tether&vs_currencies=usd'
        response = requests.get(url)
        data = response.json()
        usdt_price = data['tether']['usd']
        return usdt_price
    except Exception as e:
        print(f"Error fetching USDT price: {e}")
        return None

def calculate_usdt_value(amount_usdt):
    usdt_price = get_eth_to_usd_exchange_rate()
    if usdt_price is not None:
        value_usd = amount_usdt * usdt_price
        return value_usd
    else:
        return None




class PaymentAPIView(APIView):
    def get(self, request):
        # Get mandatory query parameters
        userId = request.GET.get("userId")
        user_address = request.GET.get("user_address")
        original_amount_usd = request.GET.get("original_amount")
        success_url = request.GET.get("success_url")
        failure_url = request.GET.get("failure_url")
        sspwallet = request.GET.get("sspwallet")

        # Check if any mandatory parameter is missing
        if not all([user_address, original_amount_usd, success_url, failure_url]):
            return Response({"message": "All mandatory query parameters are required: user_address, original_amount, sspwallet, userId, success_url, failure_url"}, status=rest_status.HTTP_400_BAD_REQUEST)

        try:
            original_amount_usd = float(original_amount_usd)
        except ValueError:
            return Response({"message": "original_amount must be a valid number"}, status=rest_status.HTTP_400_BAD_REQUEST)

        api_key = "PUVPB6IQVRMQGGCEMPSY9FQ7TUVJMJN4CH"
        token_contract_address = '0x55d398326f99059fF775485246999027B3197955'

        api_url = f'https://api.bscscan.com/api?module=account&action=tokentx&address={sspwallet}&contractaddress={token_contract_address}&apikey={api_key}'

        try:
            response = requests.get(api_url)
            if response.status_code == 200:
                data = response.json()
                if data["status"] == "1":
                    transactions = data["result"]
                    
                    # Find the last transaction for the user address
                    last_transaction = None
                    for data in reversed(transactions):
                        from_address = data.get('from').lower()  # Convert to lowercase
                        user_address_lower = user_address.lower()  # Convert to lowercase
                        if from_address == user_address_lower:
                            last_transaction = data
                            break  # Stop iteration when the last transaction for the user is found

                    if last_transaction:
                        # Process the last transaction
                        from_address = last_transaction.get('from')
                        status = last_transaction.get('status')
                        timestamp_str = last_transaction.get('timeStamp')
                        timestamp = int(timestamp_str)
                        datetime_obj = datetime.datetime.utcfromtimestamp(timestamp)
                        formatted_datetime = datetime_obj.strftime("%Y-%m-%d %H:%M:%S")
                        eth_amount = last_transaction.get('value')
                        eth_amount = int(eth_amount)
                        eth_to_usd_exchange_rate = get_eth_to_usd_exchange_rate()
                        usd_amount = eth_amount * eth_to_usd_exchange_rate
                        usd_amount_formatted = "{:.2f}".format(usd_amount / 10 ** 18)
                        paymentId = last_transaction.get('blockNumber')
                        value = int(last_transaction.get('value'))
                        amount = Wei_to_Eth(value)

                        # Calculate status
                        if original_amount_usd == float(usd_amount_formatted):
                            payment_state = "Complete"
                        elif original_amount_usd < float(usd_amount_formatted):
                            difference = float(usd_amount_formatted) - original_amount_usd
                            payment_state = f"OverPaid - {difference:.2f} USD"
                        elif original_amount_usd > float(usd_amount_formatted):
                            difference = original_amount_usd - float(usd_amount_formatted)
                            payment_state = f"UnderPaid - {difference:.2f} USD"
                        else:
                            payment_state = "In Process"

                        # Prepare response data
                        response_data = {
                            "userId": userId,
                            "user_address": from_address,
                            "datetime": formatted_datetime,
                            "paymentId": paymentId,
                            "amount": amount,
                            "usd_amount": f"{usd_amount_formatted} USD",
                            "payment_state": payment_state,
                            "status": True,
                            "success_url": success_url
                        }

                        # Send appropriate response based on status
                        return Response(response_data, status=rest_status.HTTP_200_OK)
                    else:
                        return Response({"message": f"No transactions found for user ID - {userId} with wallet address - {user_address}"},
                                        status=rest_status.HTTP_400_BAD_REQUEST)

                else:
                    return Response({"message": "Etherscan API response status is not '1'."},
                                    status=rest_status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"message": "Failed to connect to Etherscan API."},
                                status=rest_status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"message": str(e)}, status=rest_status.HTTP_500_INTERNAL_SERVER_ERROR)

class CoinBalance(APIView):
    def get(self, request, address, symbol):
        chain_symbol = request.data.get('symbol')

        if chain_symbol:
            return Response({"message": "chain_symbol is required in the request data."},
                            status=status.HTTP_400_BAD_REQUEST)

        # rpc = ChainDetails.objects.filter(chain_symbol=symbol).first()/
        rpc_url = "https://fittest-misty-seed.quiknode.pro/0a037be47a682e693c5de2a0698134eefa60928b/"

        # Connect to an Ethereum node (e.g., Infura)
        w3 = Web3(Web3.HTTPProvider(rpc_url))

        try:
            # Check ETH balance
            balance_wei = w3.eth.get_balance(address)
            print(balance_wei)
            # balance_eth = w3.fromWei(balance_wei, 'ether')

            # Token details
            token_contract_address = '0xdAC17F958D2ee523a2206206994597C13D831ec7'
            token_abi = [{"constant":True,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"name":"","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"payable":False,"stateMutability":"view","type":"function"}]

            # Load the token contract
            token_contract = w3.eth.contract(address=token_contract_address, abi=token_abi)

            # Call the balanceOf function on the token contract
            token_balance = token_contract.functions.balanceOf(address).call()

            return Response({
                "address": address,
                "balance_wei": balance_wei,
                # "balance_eth": balance_eth,
                "token_balance": token_balance
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)





def GetClientId(data):
    secret_key = get_random_bytes(16)
    print("Length of secret key:", len(secret_key))
    json_data = json.dumps(data)
    clientId, encrypted_data = encrypt(json_data.encode('utf-8'), secret_key)
    EncryptedData.objects.create(iv=clientId, encrypted_data=encrypted_data,
                                 secretId=base64.b64encode(secret_key).decode('utf-8'))  # Store the secret key
    return clientId




class PaymentBinanceAPIView(APIView):
    def get(self, request):
        userId = request.GET.get("userId")
        transaction_ID = request.GET.get("transactionID")
        original_amount_usd = request.GET.get("original_amount")

        sspwallet = SspWallet.objects.first()
        if not all([transaction_ID, original_amount_usd, userId]):
            return Response({
                                "message": "All mandatory query parameters are required: transaction_ID, original_amount, userId"},
                            status=rest_status.HTTP_400_BAD_REQUEST)

        try:
            original_amount_usd = float(original_amount_usd)
        except ValueError:
            return Response({"message": "original_amount must be a valid number"},
                            status=rest_status.HTTP_400_BAD_REQUEST)

        trx_exists = Transaction_hash.objects.filter(transaction_hash=transaction_ID).exists()
        if trx_exists:
            return Response({"message": "transaction_ID Is already used", "status":False},status=rest_status.HTTP_406_NOT_ACCEPTABLE)


        try:
            coin_instance = Coin_Details.objects.get(name='Binance')
            coin_data = Binance.objects.get(coin=coin_instance)
            api_key = coin_data.api_key
            token_contract_address = coin_data.token_address
        except:
            api_key = "PUVPB6IQVRMQGGCEMPSY9FQ7TUVJMJN4CH"
            token_contract_address = '0x55d398326f99059fF775485246999027B3197955'

        api_url = f'https://api.bscscan.com/api?module=account&action=tokentx&address={sspwallet}&contractaddress={token_contract_address}&apikey={api_key}'
        try:
            response = requests.get(api_url)
            if response.status_code == 200:
                data = response.json()
                if data["status"] == "1":
                    transactions = data["result"]

                    last_transaction = None
                    for data in reversed(transactions):
                        hash_id = data.get('hash').lower()  
                        transaction_ID_lower = transaction_ID.lower()
                        if hash_id == transaction_ID_lower:
                            last_transaction = data
                            break 

                    if last_transaction:
                        transaction_ID = last_transaction.get('hash')
                        from_address = last_transaction.get('from')
                        timestamp_str = last_transaction.get('timeStamp')
                        timestamp = int(timestamp_str)
                        datetime_obj = datetime.datetime.utcfromtimestamp(timestamp)
                        formatted_datetime = datetime_obj.strftime("%Y-%m-%d %H:%M:%S")
                        eth_amount = last_transaction.get('value')
                        eth_amount = int(eth_amount)
                        eth_to_usd_exchange_rate = get_eth_to_usd_exchange_rate()
                        usd_amount = eth_amount * eth_to_usd_exchange_rate
                        usd_amount_formatted = "{:.2f}".format(usd_amount / 10 ** 18)
                        paymentId = last_transaction.get('blockNumber')
                        value = int(last_transaction.get('value'))
                        amount = Wei_to_Eth(value)

                        # Calculate status
                        if original_amount_usd == float(usd_amount_formatted):
                            payment_state = "Complete"
                        elif original_amount_usd < float(usd_amount_formatted):
                            difference = float(usd_amount_formatted) - original_amount_usd
                            payment_state = f"OverPaid - {difference:.2f} USD"
                        elif original_amount_usd > float(usd_amount_formatted):
                            difference = original_amount_usd - float(usd_amount_formatted)
                            payment_state = f"UnderPaid - {difference:.2f} USD"
                        else:
                            payment_state = "In Process"

                        # Prepare response data
                        response_data = {
                            "payment_mode": "Binance",
                            "userId": userId,
                            "transaction_ID":transaction_ID,
                            "user_address": from_address,
                            "datetime": formatted_datetime,
                            "paymentId": paymentId,
                            "amount": amount,
                            "usd_amount": f"{usd_amount_formatted} USD",
                            "payment_state": payment_state,
                            "status": True
                        }
                        Transaction_hash.objects.create(transaction_hash=transaction_ID)

                        cliId = GetClientId(response_data)
                        combined_response_data = {
                            'response_data': response_data,
                            'clientId': cliId
                        }
                        return Response(combined_response_data, status=rest_status.HTTP_200_OK)
                    else:
                        response_data1 = {
                                            "message": f"No transactions found for user ID - {userId} with transaction ID - {transaction_ID}","status":False}
                        cliId = GetClientId(response_data1)
                        response_data = {"status": False}
                        combined_response_data = {
                            "message": f"No transactions found for user ID - {userId} with transaction ID - {transaction_ID}",
                            "clientId": cliId, "response_data": response_data}
                        return Response(combined_response_data, status=rest_status.HTTP_404_NOT_FOUND)
                else:
                    response_data = {
                        "message": "Bscscan API response status is not '1'.",
                        "status": status.HTTP_400_BAD_REQUEST
                    }
                    return Response(response_data,status.HTTP_400_BAD_REQUEST)
            else:
                response_data = {
                    "message": "Failed to connect to Bscscan API.",
                    "status": status.HTTP_500_INTERNAL_SERVER_ERROR
                }
                return Response(response_data,status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            response_data = {
                "message": str(e),
                "status": status.HTTP_500_INTERNAL_SERVER_ERROR
            }
            return Response(response_data, status.HTTP_500_INTERNAL_SERVER_ERROR)
