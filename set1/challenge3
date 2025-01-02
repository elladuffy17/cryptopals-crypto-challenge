# Single-byte XOR cipher

# Example:
# The hex encoded string:

# 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
# ... has been XOR'd against a single character. Find the key, decrypt the message.

# You can do this by hand. But don't: write code to do it for you.
# How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. 
# Evaluate each output and choose the one with the best score.

import binascii
from collections import Counter

# ETAOIN SHRDLU ... the twelve most common letters in English, in order of most frequently used to least frequently used
occurance_english = {
    'a': 8.2389258,    'b': 1.5051398,    'c': 2.8065007,    'd': 4.2904556,
    'e': 12.813865,    'f': 2.2476217,    'g': 2.0327458,    'h': 6.1476691,
    'i': 6.1476691,    'j': 0.1543474,    'k': 0.7787989,    'l': 4.0604477,
    'm': 2.4271893,    'n': 6.8084376,    'o': 7.5731132,    'p': 1.9459884,
    'q': 0.0958366,    'r': 6.0397268,    's': 6.3827211,    't': 9.1357551,
    'u': 2.7822893,    'v': 0.9866131,    'w': 2.3807842,    'x': 0.1513210,
    'y': 1.9913847,    'z': 0.0746517
}
dist_english = list(occurance_english.values())

scoring = {}

def single_xor(byte_string, key):
    return bytes(b ^ key for b in byte_string)

def word_frequency(text):
    # we see that key 88 makes a string that aligns with the english language... but how do we quantify this?
    # Solution: Fitting Quotient

    counter = Counter(text) #counts the occurances of objects. so ella has l:2
    dist_text = [
        (counter.get(ch, 0) * 100) / len(text)
        for ch in occurance_english
    ] # this computes the frequency that the different characters of the english langauge occur in the inputted text
    return sum([abs(a - b) for a, b in zip(dist_english, dist_text)]) / len(dist_text) #the fitting quotient computation

    
user_input = str(input("Enter your first string: "))
bytes1 = binascii.unhexlify(user_input)

# So these bytes have been XOR'd with a single character to conceal a message
# If you have: c = a^b; You can get a or b back if you have the other value available: a = c^b

# There are a very limited number of possible encryption keys - 256
# Since the key is just one byte, then just try all numbers from 0 (0000 0000) to 255 (1111 1111)

for char1 in range(0, 256):
    result = single_xor(bytes1, char1)
    str_result = str(result)[2:-1] #trime the b' ... ' from the string we got from converting bytes object. use slicing technique to start at index 2 and go until
    #print("the key: ", char1, "decrypted this message: ", str_result)
    # Looks like key 88 is correct... how do we figure out with code that this is the right one?? use letter frequency
    scoring[char1] = word_frequency(str_result)

winning_key = min(scoring, key = scoring.get)
secret_message = str(single_xor(bytes1, winning_key))[2:-1]
print("The key is ", winning_key, "which is used to decrypt the secret message: ", secret_message)


