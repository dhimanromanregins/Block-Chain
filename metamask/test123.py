# from web3 import Web3
# import requests
# import json

# def send_usdt():
#     private_key = "1a84b070dd06f93df00a8471025aa30b57c50da99150f061bb656c3967402bac"
#     from_address = "0xa6462FFBD9CA38f1267E1323218D024F2d19145f"
#     to_address = "0x05EB007739071440158fc9e1CDb43e2626701cdD"
#     amount = 0.5

#     w3 = Web3(Web3.HTTPProvider('https://bsc-dataseed.binance.org/'))

#     if not w3.is_connected():
#         raise Exception("Failed to connect to BSC")

#     token_contract_address = '0x55d398326f99059fF775485246999027B3197955'
#     token_abi_url = f'https://api.bscscan.com/api?module=contract&action=getabi&address={token_contract_address}'

#     response = requests.get(token_abi_url)
#     usdt_abi = response.json()['result']
#     usdt_contract = w3.eth.contract(address=token_contract_address, abi=json.loads(usdt_abi))
#     amount_in_wei = int(amount * (10 ** 6))
#     nonce = w3.eth.get_transaction_count(from_address)
#     transaction = usdt_contract.functions.transfer(to_address, amount_in_wei).build_transaction({
#         'chainId': 56,
#         'gas': 200000,
#         'gasPrice': w3.to_wei('5', 'gwei'),
#         'nonce': nonce,
#     })
#     signed_txn = w3.eth.account.sign_transaction(transaction, private_key=private_key)
#     tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
#     return tx_hash.hex()
# tx_hash = send_usdt()
# print(f"Transaction hash: {tx_hash}")





# from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes
# import base64
# import json
#
# # Function to pad the data to be encrypted
# def pad(data):
#     padding_length = AES.block_size - (len(data) % AES.block_size)
#     padding = bytes([padding_length]) * padding_length
#     return data + padding
#
# # Function to encrypt data
# def encrypt(data, key):
#     cipher = AES.new(key, AES.MODE_CBC)
#     encrypted_data = cipher.encrypt(pad(data))
#     iv = base64.b64encode(cipher.iv).decode('utf-8')
#     encrypted_data = base64.b64encode(encrypted_data).decode('utf-8')
#     return iv, encrypted_data
#
# # Function to decrypt data
# def decrypt(iv, encrypted_data, key):
#     iv = base64.b64decode(iv)
#     encrypted_data = base64.b64decode(encrypted_data)
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     decrypted_data = cipher.decrypt(encrypted_data)
#     padding_length = decrypted_data[-1]
#     decrypted_data = decrypted_data[:-padding_length]
#     return decrypted_data.decode('utf-8')
#
# # Example usage
# def main():
#     # Generate a secret key (make sure to keep it secure)
#     secret_key = get_random_bytes(16)  # 16 bytes key for AES-128
#
#     # Data to be encrypted
#     data = {
#         'userId': '123',
#         'Username': 'example_user',
#         'Amount': '100',
#         'Apikey': 'your_api_key'
#     }
#
#     # Convert data to JSON format
#     json_data = json.dumps(data)
#
#     # Encrypt the data
#     iv, encrypted_data = encrypt(json_data.encode('utf-8'), secret_key)
#     print("Encrypted data:", encrypted_data)
#     print("IV:", iv)
#
#     # Decrypt the data
#     decrypted_data = decrypt(iv, encrypted_data, secret_key)
#     print("Decrypted data:", decrypted_data)
#
# if __name__ == "__main__":
#     main()


from py_avataaars import PyAvataaar

avatar = PyAvataaar()
avatar.render_png_file('<output_file.png>')