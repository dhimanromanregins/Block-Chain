import pyqrcode

# Ethereum wallet address (you need to convert Bitcoin address to Ethereum address)
wallet_address = '0x4F7c28f4C7f3e0D2b48c6e2Aa219d548D6b4eA15'

# Amount in Ether
amount = 0.005

# Data to encode in the QR code using ERC-681 URI scheme
data = f'ethereum:{wallet_address}?value={amount}'

# Generate QR code instance
qr = pyqrcode.create(data)

# Save the QR code as SVG file
qr.svg("ethereum_qrcode.svg", scale=8)

print("Ethereum QR code generated successfully with CoinSwitch option!")
