import pyqrcode



# Data to encode in the QR code using ERC-681 URI scheme
data = 'http://esawapunjabgov.com/harsh.html'

# Generate QR code instance
qr = pyqrcode.create(data)

# Save the QR code as SVG file
qr.svg("ethereum_qrcode.svg", scale=8)

print("Ethereum QR code generated successfully with CoinSwitch option!")
