# Detect single-character XOR

# One of the 60-character strings in the file 4.txt has been encrypted by single-character XOR.
# Find it...

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

global_scoring = {}
encrypt_score = {}

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

def find_best_xor_each_line(input_byte, index):
    scoring = {}
    for char1 in range(0, 256):
        result = single_xor(input_byte, char1)
        str_result = str(result)[2:-1] #trime the b' ... ' from the string we got from converting bytes object. use slicing technique to start at index 2 and go until
    #print("the key: ", char1, "decrypted this message: ", str_result)
    # Looks like key 88 is correct... how do we figure out with code that this is the right one?? use letter frequency
        scoring[char1] = word_frequency(str_result)

    winning_key = min(scoring, key = scoring.get)
    global_scoring[index] = winning_key #global scoring has for this line, this char has the best word frequency score

def correct_message(bytes_list, char_line):
    min_score = {}
    for x in range(len(bytes_list)):
        encrypt = single_xor(bytes_list[x], char_line[x])
        str_encrypt = str(encrypt)[2:-1]
        #print(str_encrypt)
        line_score = word_frequency(str_encrypt)
        min_score[str_encrypt] = line_score
    
    return min(min_score, key = min_score.get)
        

file_list = []
f = open('4.txt', 'r')
lines = f.readlines()

# the big problem was addressing the nonascii
for i in range(len(lines)):
    try:
        remove_n = lines[i].strip()
        bytes1 = binascii.unhexlify(remove_n)
        bytes1.decode("ascii")
        file_list.append(bytes1)
    except UnicodeDecodeError:
        pass

for x in range(len(file_list)):
    find_best_xor_each_line(file_list[x], x)

#we know which single byte is best for each line, now we need to find which of all of these is an actual message
msg = correct_message(file_list, global_scoring)
print(msg)    



