import requests
from web3 import Web3
import json

def get_token_logo_path(address):
    try:
        # Make an API request to CoinGecko to get token metadata
        api_url = f'https://api.coingecko.com/api/v3/coins/ethereum/contract/{address}'
        response = requests.get(api_url)
        data = response.json()

        # Extract the logo URL from the response
        token_logo_url = data.get('image', {}).get('small')

        if token_logo_url:
            return token_logo_url
        else:
            return None
    except Exception as e:
        print(f'Error: {e}')
        return None
    

def calculate_99_percent(total_amount):
    result = amount * 0.99
    rounded_result = round(result, 3)
    return rounded_result



def send_usdt(total_amount, to_address):
    private_key = "1a84b070dd06f93df00a8471025aa30b57c50da99150f061bb656c3967402bac"
    from_address = "0xa6462FFBD9CA38f1267E1323218D024F2d19145f"
    # to_address = "0x05EB007739071440158fc9e1CDb43e2626701cdD"
    # amount = 0.5
    amount  = calculate_99_percent(total_amount, to_address)
    w3 = Web3(Web3.HTTPProvider('https://bsc-dataseed.binance.org/'))

    if not w3.is_connected():
        raise Exception("Failed to connect to BSC")

    token_contract_address = '0x55d398326f99059fF775485246999027B3197955'
    token_abi_url = f'https://api.bscscan.com/api?module=contract&action=getabi&address={token_contract_address}'

    response = requests.get(token_abi_url)
    usdt_abi = response.json()['result']
    usdt_contract = w3.eth.contract(address=token_contract_address, abi=json.loads(usdt_abi))
    amount_in_wei = int(amount * (10 ** 6))
    nonce = w3.eth.get_transaction_count(from_address)
    transaction = usdt_contract.functions.transfer(to_address, amount_in_wei).build_transaction({
        'chainId': 56,
        'gas': 200000,
        'gasPrice': w3.to_wei('5', 'gwei'),
        'nonce': nonce,
    })
    signed_txn = w3.eth.account.sign_transaction(transaction, private_key=private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    return tx_hash.hex()



