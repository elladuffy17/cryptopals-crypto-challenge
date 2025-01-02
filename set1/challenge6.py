# Break repeating-key XOR

# The file 6.txt has been base64'd after being encrypted with repeating-key XOR.

# Decrypt it.

# Here's how:

#  1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.

#  2. Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. 
#  The distance between:
#         this is a test
#  and
#         wokka wokka!!!
# is 37. Make sure your code agrees before you proceed.

#  3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this 
#  result by dividing by KEYSIZE.

#  4. The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE 
#  blocks instead of 2 and average the distances.

#  5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.

#  6. Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.

#  7. Solve each block as if it was single-character XOR. You already have code to do this.

#  8. For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and
#  you have the key.

# This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "
# Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important.#


# First is our edit distance/Hamming distance function
# It is used for error detection or error correction when data is transmitted over computer networks

import base64
from base64 import b64decode
import sys
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

input1="this is a test"
input2="wokka wokka!!!"
hd_dict = {}

def hamming_distance(string1, string2):
    # conversion of a string to it’s binary equivalent
    bits1 =str(''.join(format(ord(i), '08b') for i in string1))
    bits2 =str(''.join(format(ord(i), '08b') for i in string2))
    #print(len(bits1))

    hamming_d = 0

    if len(bits1)!=len(bits2):
        return -1 #error
    else:
        for x in range(0, len(bits1)):
            if (bits1[x]!=bits2[x]):
                hamming_d +=1
    
    return hamming_d

def hd_keysize(final, keysize):
    double_keysize = keysize * 2
    blocks = len(final)/double_keysize - 1

    if blocks <= 2:
		# Not enough blocks to calculate a meaningful distance
        pass
    
    distance = 0
    # We loop divide the ciphertext in blocks and loop through them to calculate the hamming distanc
    for block in range(0, int(blocks)):
        block1 = final[block*double_keysize : block*double_keysize+keysize] #grabs the string from one index to another
        block2 = final[block*double_keysize+keysize : block*double_keysize+2*keysize]

        hd = hamming_distance(block1, block2)
        distance += hd

    normalized_d = distance / keysize / blocks
    hd_dict[keysize] = normalized_d
              
def cipher_transponse(org_list, org_key):

    #the new length of each block
    b_length = len(org_list)
    #the number of new blocks will be equal to org_key
    transpose = [''] * org_key
   
    for j in range(b_length):
        new = org_list[j]
        #new_b = new.encode(encoding="utf-8")
        n_seperate = [new[a:a+1] for a in range(len(new))]
    
        for x in range(0, org_key):
            if len(n_seperate) != org_key:
                #won't have proper indexing
                pass
            else:
                transpose[x] = transpose[x] + n_seperate[x]

    return transpose

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

def repeating_xor(input, key_list):
    encryption = []
    #print(input)
    for b in range(len(input)):    
        encryption.append(ord(input[b]) ^ key_list[b % len(key_list)])
    
    return(bytes(encryption))


f = open('6.txt', 'r') # this file has been base64d -- 6 bits
lines = f.readlines()
file_list = []

#since our hamming distance takes in strings, we must convert from base 64
for i in range(len(lines)):
    try:
        remove_n = lines[i].rstrip('\n')
        b64_bytes = remove_n.encode("ascii")

        string_bytes = base64.b64decode(b64_bytes)
        #print(string_bytes)
        final_string = string_bytes.decode("ascii")
        #print(final_string)
        file_list.append(final_string)
    except UnicodeDecodeError:
        pass

final = (''.join(file_list))

for keysize in range(2, 41):
    hd_keysize(final, keysize)

winning_key = min(hd_dict, key = hd_dict.get)
winning_block = []
for idx in range(0, len(final), winning_key):
    winning_block.append(final[idx : idx + winning_key])

print("The winning key: ", winning_key)

# now we have broken the ciphertext into blocks of the winning KEYSIZE length. winning_block is a list that holds these blocks
# now we must transpose this.... 
# a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
#print("Original:")
#print(winning_block)
#print("\n")

#print("Transposed:")
transposed_block = cipher_transponse(winning_block, winning_key)
#print(transposed_block)
#print("\n")

#Solve each block as if it was single-character XOR
#The winning key is how many blocks we have
theKey = []
for i_block in range(winning_key):
    #convert from string to bytes
    string_b = bytes(transposed_block[i_block], 'utf-8')
    #call single byte xor
    for char1 in range(0, 256):
        result = single_xor(string_b, char1)
        str_result = str(result)[2:-1] #trime the b' ... ' from the string we got from converting bytes object. use slicing technique to start at index 2 and go until
        scoring[char1] = word_frequency(str_result)
    
    #For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and
    # you have the key.
    winning_key = min(scoring, key = scoring.get)
    theKey.append(winning_key)

complete_key = bytes(theKey)
print("The key used to encrypt is: ", complete_key)
key_list = [x for x in complete_key]

# Now that we have the key, complete repeating key xor
final_xor = repeating_xor(final, key_list)
print("The message: \n")

print(final_xor)