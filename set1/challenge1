# Convert hex to base64

# Example, the string:
#   49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
# Should produce:
#   SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

# Cryptopal Rules: 
#    Always operate on raw bytes, never on encoded strings
#    Only use hex and base64 for pretty-printing.

import base64
import binascii

# First will do it with hard coded values, then take user input
#hex = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
hex_user = input("Enter your hex string to be converted: ")

hex = str(hex_user)
raw_bytes = binascii.unhexlify(hex)

base_64 = base64.standard_b64encode(raw_bytes)
print(base_64)
