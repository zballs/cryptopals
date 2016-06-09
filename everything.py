import time
from copy import deepcopy
from random import sample, randint
from Crypto.Cipher import AES
import base64
import binascii
from itertools import combinations, cycle, starmap
import codecs
from statistics import mode
import struct

freqs = {
    b'a': 0.08167,
    b'b': 0.01492,
    b'c': 0.02782,
    b'd': 0.04253,
    b'e': 0.12702,
    b'f': 0.02228,
    b'g': 0.02015,
    b'h': 0.06094,
    b'i': 0.06966,
    b'j': 0.00153,
    b'k': 0.00772,
    b'l': 0.04025,
    b'm': 0.02406,
    b'n': 0.06749,
    b'o': 0.07507,
    b'p': 0.01929,
    b'q': 0.00095,
    b'r': 0.05987,
    b's': 0.06327,
    b't': 0.09056,
    b'u': 0.02758,
    b'v': 0.00978,
    b'w': 0.02361,
    b'x': 0.00015,
    b'y': 0.01974,
    b'z': 0.00074
}

def crypt_xor(plainbytes,keybytes):
    return bytes([b1 ^ b2 for b1, b2 in zip(plainbytes, cycle(keybytes))])

def decrypt_ecb(cryptbytes,keybytes):
    cipher = AES.new(keybytes)
    return cipher.decrypt(cryptbytes)

def encrypt_ecb(plaintext,keybytes):
    cipher = AES.new(keybytes)
    try:
        encrypted = cipher.encrypt(plaintext)
        return encrypted
    except:
        plaintext_padded = pkcs7(plaintext,16)
        encrypted = cipher.encrypt(plaintext_padded)
        return encrypted 

# Padding
def pkcs7(textbytes,blocksize):
    padding = blocksize - (len(textbytes) % blocksize)
    result = textbytes + bytes([padding]*padding)
    return result

# Unpad
def unpad(textbytes):
    padding = textbytes[-textbytes[-1]:]
    if all([padding[p]==len(padding) for p in range(len(padding))]):
        textbytes = textbytes[:-len(padding)]
    return textbytes

# Scoring
def score(textbytes):
    points = 0
    for char in textbytes:
        if chr(char).lower() in freqs:
            points += 1+ freqs[chr(char).lower()]
    return points

def recurrence(textbytes):
    r = [0] * 256
    for char in textbytes:
        r[char] += 1
    recurrent = max(r) / len(textbytes)
    return recurrent
        

def encrypt_cbc(textbytes,keybytes):
    
    cryptbytes = b''
    
    iv = bytes([0] * len(keybytes))
    blocksize = len(iv)
    
    for i in range(0,len(textbytes), blocksize):
        chunk = textbytes[i:i+blocksize]
        if len(chunk) < blocksize:
            chunk = pkcs7(chunk,blocksize)
        cryptchunk = encrypt_ecb(crypt_xor(chunk,iv),keybytes)
        cryptbytes += cryptchunk 
        iv = cryptchunk
    return cryptbytes

def decrypt_cbc(cryptbytes,keybytes):
    
    plainbytes = []
    
    iv = bytes([0] * len(keybytes))
    blocksize = len(iv)
    
    for j in range(0,len(cryptbytes),blocksize):
        cryptchunk = cryptbytes[j:j+blocksize]
        chunk = crypt_xor(decrypt_ecb(cryptchunk,keybytes),iv) ## reverse reverse 
        # Check if padding valid 
        if chunk != unpad(chunk):
            valid_padding = True
        else:
            valid_padding = False
        chunk = unpad(chunk)
        plainbytes.append(chunk)
        iv = cryptchunk
    return b''.join(plainbytes), valid_padding


def genBytes(numBytes):
    return bytes([randint(0,255) for byte in range(numBytes)])

def encryption_oracle(textbytes,keysize):
    keybytes = genBytes(keysize)
    before = randint(5,10)
    after = randint(5,10)
    textbytes = genBytes(before) + textbytes + genBytes(after)
    cbc = randint(0,1)
    if cbc:
        print('cbc')
        crypto = encrypt_cbc(textbytes,keybytes)
    else:
        print('ecb')
        sixteenBytes = pkcs7(textbytes,keysize) #repadding... Genius!!
        crypto = encrypt_ecb(sixteenBytes,keybytes)
    return crypto

def detectEncryption(crypto,keysize):
    
        totals = {}

        totals['cbc'] = -float("inf")
        totals['ecb'] = -float("inf")

        for iter2 in range(10000):

            randkey = genBytes(keysize)

            cbc = decrypt_cbc(crypto,randkey)
            cbc_score = score(cbc)
            cbc_recurrence = recurrence(cbc)
            cbc_total = cbc_score + cbc_recurrence

            ecb = decrypt_ecb(crypto,randkey)
            ecb_score = score(ecb)
            ecb_recurrence = recurrence(ecb)
            ecb_total = ecb_score + ecb_recurrence

            if cbc_total > totals['cbc']:
                totals['cbc'] = cbc_total
            if ecb_total > totals['ecb']:
                totals['ecb'] = ecb_total

        if totals['cbc'] >= totals['ecb']:
            return 'cbc'

        else:
            return 'ecb'

randkey = genBytes(16)
unknownStr = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
unknownBytes = base64.b64decode(unknownStr)

def encryption_oracle2(textbytes):
    blocksize = len(randkey)
    textbytes += unknownBytes
    textbytes_padded = pkcs7(textbytes,blocksize)
    crypto = encrypt_ecb(textbytes_padded,randkey)
    return crypto   

def brute_ecb_blocksize(crypt_method):
    REPEATS = 20
    for blocksize in range(4,128):
        # Generate random sequence of bytes as motif
        motif = sample(range(0,256),blocksize)
        # Repeat motif to get plaintext bytes 
        textbytes = bytes(motif) * REPEATS 
        # Encrypt dat shit
        cryptbytes = crypt_method(textbytes,randkey,0)
        # Find repeat patterns in encrypted shit 
        max_repeats, _ = find_longest_repeat(cryptbytes,blocksize)
        if max_repeats in [REPEATS-1,REPEATS]:
            return blocksize
    return None
    
def find_longest_repeat(data,blocksize):
    chunks = [data[i:i+blocksize] for i in range(0,len(data),blocksize)]
    prev = None
    count = 1
    max_result = (0,None)
    for chunk in chunks:
        if chunk == prev:
            count += 1
        else:
            count = 1
        if count > max_result[0]:
            max_result = (count, chunk)
        prev = chunk
    return max_result

def block_oracle(crypt_method,blocksize,textbytes):
    assert len(textbytes) == blocksize
    REPEATS = 10
    repeated_bytes = textbytes * REPEATS
    inbytes = b'\x00'.join([repeated_bytes] * blocksize) 
    cryptbytes = crypt_method(inbytes,randkey)
    max_repeats, cryptbytes = find_longest_repeat(cryptbytes,blocksize)
    if max_repeats == REPEATS:
        return cryptbytes
    raise Exception('Failed to find encrypted bytes')
    
def build_lookup_table(crypt_method,blocksize,prefix):
    assert len(prefix) == blocksize - 1
    table = {}
    for x in range(256):
        testcase = prefix + bytes([x])
        crypt_chunk = block_oracle(crypt_method,blocksize,testcase)
        table[crypt_chunk] = x
    return table
            
    
def decryptUnknown():
    blocksize = brute_ecb_blocksize(encryption_oracle2)
    blocks = 9
    mybytes = genBytes(blocks*blocksize)
    b = b''
    for j in range(1,len(mybytes)):
        short = mybytes[:-j]
        output = encryption_oracle2(short)
        outputs = []
        for i in range(256):
            testbytes = short + b + bytes(chr(i),encoding='utf-8')
            outputs.append(encryption_oracle2(testbytes))
        for idx, o in enumerate(outputs):
            if o[:blocks*blocksize-1] == output[:blocks*blocksize-1]:
                b += bytes(chr(idx),encoding='utf-8')
    print(b)
    
    
def KV_parsing(string):
    dictionary = {}
    _string = deepcopy(string)
    while True:  
        key = _string[:_string.index(b'=')]
        try:
            value = _string[_string.index(b'=')+1:_string.index(b';')]
            dictionary[key] = value
            _string = _string[_string.index(b';')+1:]
        except:
            value = _string[_string.index(b'=')+1:]
            dictionary[key] = value
            break
    return dictionary 

def profile_for(string):    
    d = {}
    d['email'] = string 
    d['uid'] = str(10)
    if string == admin_email:
        d['role'] = 'admin'
    else:
        d['role'] = 'user'
    encoding = 'email=' + d['email'] +'&uid=' + d['uid'] + '&role=' + d['role']
    return encoding
    
def encryptProf(string):
    encoding = b'' + bytes(profile_for(string),encoding='utf-8')
    encrypted = encrypt_ecb(encoding,randkey)
    return encrypted
    
def decryptParseProf(textbytes):
    decrypted = decrypt_ecb(textbytes,randkey)
    unpadded = unpad(decrypted)
    hex1 = binascii.b2a_hex(unpadded).decode()
    string = binascii.a2b_hex(hex1).decode(encoding='windows-1252')
    return KV_parsing(string)


prepend = genBytes(randint(2,16))

def encryption_oracle3(textbytes):
    blocksize = len(randkey)
    textbytes = prepend + textbytes + unknownBytes
    textbytes_padded = pkcs7(textbytes,blocksize)
    crypto = encrypt_ecb(textbytes_padded,randkey)
    return crypto

def decryptUnknown2():
    blocksize = brute_ecb_blocksize(encryption_oracle3)
    blocks = 9
    mybytes = genBytes(blocks*blocksize)
    output3 = encryption_oracle3(mybytes)
    pre = genBytes(blocksize)
    for p in range(1,blocksize):
        long = pre[:p] + mybytes
        output2 = encryption_oracle2(long)
        if list(bytes(output2))[blocksize:] == list(bytes(output3))[blocksize:]:
            preLength = p
    moreBytes = genBytes(blocksize - (preLength % blocksize))
    mybytes = moreBytes + mybytes
    end = len(mybytes)
    b = b''
    for j in range(1,len(mybytes)-len(moreBytes)):
        short = mybytes[:-j]
        output = encryption_oracle3(short)
        outputs = []
        for k in range(256):
            testbytes = short + b + bytes(chr(k),encoding='utf-8')
            outputs.append(encryption_oracle3(testbytes))
        for idx, o in enumerate(outputs):
            if o[:end] == output[:end]:
                b += bytes(chr(idx),encoding='utf-8')
    return b

def encrypt_cbc2(mystring):
    if mystring.find(';admin=true;') == -1:
        bitstr = b'comment1=cooking%20MCs;userdata=' + bytes(mystring,encoding='utf-8') + b';comment2=%20like%20a%20pound%20of%20bacon'
        crypto = encrypt_cbc(bitstr,randkey)
        return crypto
    return None

def decrypt_cbc2(cryptbytes):
    if cryptbytes:
        textbytes = decrypt_cbc(cryptbytes,randkey)
        if textbytes.find(b';admin=true;') != -1:
            return True, textbytes
    return False, textbytes



def changeCrypto(textbytes, cryptbytes, target):
    result = b';admin=true;'
    blocksize = len(randkey)
    cryptblocks = [cryptbytes[i:i+blocksize] for i in range(0,len(cryptbytes),blocksize)]
    textblocks = [textbytes[i:i+blocksize] for i in range(0,len(textbytes),blocksize)]
    target = target - 1
    before = target - 1
    newblock = bytes([textblocks[target][i] ^ result[i] ^ cryptblocks[before][i] for i in range(len(result))])
    newcrypt = b''.join(cryptblocks[:before]) + newblock + b''.join([cryptblocks[before][len(result):]]) + b''.join(cryptblocks[before+1:])
    return newcrypt

strings = [
    'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
    'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
    'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
    'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
    'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
    'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
    'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
    'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
    'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
    'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']

def cbc_oracle(bitstr):
    blocksize = len(randkey)
    randnum = randint(0,9)
    padded_string = pkcs7(bitstr,blocksize)
    crypto = encrypt_cbc(padded_string,randkey)
    return crypto
    

def decrypt_checkPadding(crypto):
    textbytes, valid_padding = decrypt_cbc(crypto,randkey)
    if valid_padding:
        return textbytes, True
    return textbytes, False

def cbc_oracle_attack(cryptbytes):
    blocksize = len(randkey)
    last = int(len(cryptbytes) / blocksize)
    cryptblocks = [cryptbytes[i:i+blocksize] for i in range(0,len(cryptbytes),blocksize)] 
    iv = [0]*len(randkey)
    allchars = b''
    while last > 0:
        target = last - 1
        before = target - 1
        intermediates = []
        textchars = b''
        for k in range(blocksize):
            cryptchars = b''
            for I in intermediates:
                cryptchar = bytes([I ^ (k+1)])
                cryptchars = cryptchar + cryptchars
            for num in range(256):
                newcrypto = b''.join(cryptblocks[:before]) + genBytes(blocksize-k-1) + bytes([num]) + cryptchars + bytes([b for b in cryptblocks[target]])
                textbytes, valid_padding = decrypt_checkPadding(newcrypto)
                if valid_padding:
                    intermediate = num ^ (k+1)
                    if last > 1:
                        textchar = bytes([cryptblocks[before][blocksize-k-1] ^ intermediate])
                    else:
                        textchar = bytes([iv[blocksize-k-1] ^ intermediate])
                    intermediates.append(intermediate)
                    textchars = textchar + textchars
        allchars = textchars + allchars
        last = last - 1
    print(allchars)

def encrypt_ctr(textbytes,keybytes,nonce):
    blocksize = len(keybytes)
    half = int(blocksize / 2)
    counter = 0
    crypto = b''
    for i in range(0,len(textbytes),blocksize):
        form = bytes([nonce]*half) + bytes([counter]) + bytes(half-1)
        keystream = encrypt_ecb(form,keybytes)
        if len(textbytes) - i >= blocksize:
            xor = crypt_xor(keystream,textbytes[i:i+blocksize])
        else:
            xor = crypt_xor(keystream[:len(textbytes)-i],textbytes[i:])
        crypto += xor
        counter += 1
    return crypto

def decrypt_ctr(crypto, keybytes, nonce):
    blocksize = len(keybytes)
    half = int(blocksize / 2)
    counter = 0
    textbytes = b''
    for i in range(0,len(crypto),blocksize):
        form = bytes([nonce]*half) + bytes([counter]) + bytes(half-1)
        keystream = encrypt_ecb(form,keybytes)
        if len(crypto) - i >= blocksize:
            xor = crypt_xor(keystream,crypto[i:i+blocksize])
        else:
            xor = crypt_xor(keystream[:len(crypto)-i],crypto[i:])
        textbytes += xor
        counter += 1
    return textbytes



def break_ctr():
    with open('C:/Users/Zachary/Desktop/challenge20.txt') as file:
        reader = file.readlines()
        items = list(reader)
    for idx, item in enumerate(items):
        items[idx] = base64.b64decode(item)
    encryptions = []
    for item in items:
        encryptions.append(encrypt_ctr(item,randkey,0))
    shortest = float("inf")
    for e in encryptions:
        if len(e) < shortest:
            shortest = len(e)
    bitstr = b''
    for idx, e in enumerate(encryptions):
        encryptions[idx] = e[:shortest]
        bitstr += encryptions[idx]
    
    blocksize = shortest
    blocks = [bitstr[i:i+blocksize] for i in range(0,len(bitstr),blocksize)]
    newblocks = [None] * blocksize
    for j in range(blocksize):
        newblocks[j] = b''
        for b in blocks:
            try:
                newblocks[j] += bytes([b[j]])
            except:
                pass
    key = b''
    for nb in newblocks:
        biggest = -float("inf")
        for num in range(256):
            score = 0
            xor = crypt_xor(nb,bytes([num]))
            for x in xor:
                char = bytes([x])
                try:
                    if char.lower() in freqs:
                        score += freqs[char.lower()]
                except:
                    pass
            if score > biggest:
                biggest = score
                best = bytes([num])
        key += best
    print()
    
# (w, n, m, r) = (32, 624, 397, 31)
# a = 9908B0DF16
# (u, d) = (11, FFFFFFFF16)
# (s, b) = (7, 9D2C568016)
# (t, c) = (15, EFC6000016)
# l = 18
# upper_mask = 0x80000000
# lower_mask = 0x7fffffff

def get32(x):
    return int(0xFFFFFFFF & x)
    
class MT(object):
    n = 624
    def __init__(self):
        self.state = [0] * MT.n
        
    def seed_mt(self,seed):
        self.index = MT.n
        self.state[0] = seed
        for i in range(1,MT.n):
            self.state[i] = get32(1812433253 * (self.state[i-1] ^ (self.state[i-1] >> 30)) + i)
    
    def extract_number(self):
        if self.index >= MT.n:
            self.twist()
        y = self.state[self.index]
        y ^= (y >> 11) & 0xFFFFFFFF
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        
        self.index += 1
        return get32(y)

    def twist(self):
        for i in range(MT.n):
            x = get32((self.state[i] & 0x80000000) + (self.state[(i+1)%  MT.n] & 0x7fffffff))
            xA = x >> 1
            if x % 2 != 0:
                xA = xA ^ 0x9908b0df
            self.state[i] = self.state[(i+397) % MT.n] ^ xA
        self.index = 0

def find_seed():
    mt = MT()
    randnum1 = randint(2,60)
    randnum2 = randint(2,60)
    randnum3 = randint(2,60)
    time.sleep(randnum1)
    timestamp = int(time.time())
    print(timestamp)
    mt.seed_mt(timestamp)
    time.sleep(randnum2)
    output = mt.extract_number()
    time.sleep(randnum3)
    t = int(time.time())
    while True:
        mt.seed_mt(t)
        output2 = mt.extract_number()
        if output == output2:
            break
        t -= 1  
    print(t)
    
def untemper(y):
    z = get32(y)
    z = '{0:0>32b}'.format(z)

    # Undo Step 4
    first18 = z[:18]
    first14 = int(first18[:14],2)
    last14 = int(z[-14:],2)
    xor1 = '{0:0>32b}'.format(first14 ^ last14)[-14:]
    z = first18 + xor1

    # Undo Step 3
    last15 = z[-15:]
    next15 = z[-30:-15]
    num = '{0:0>32b}'.format(0xEFC60000)
    xor2 = '{0:0>32b}'.format(int(next15,2) ^ (int(last15,2) & int(num[-30:-15],2)))[-15:]
    first2 = z[:2]
    z = first2 + xor2 + last15
    xor3 = '{0:0>32b}'.format(int(first2,2) ^ (int(z[-17:-15],2) & int(num[:2],2)))[-2:]
    z = xor3 + xor2 + last15

    # Undo Step 2
    num = '{0:0>32b}'.format(0x9D2C5680)
    last7 = z[-7:]
    zz = last7
    i = -14
    while i > -32:
        next7 = z[i:i+7]
        xor4 = '{0:0>32b}'.format(int(next7,2) ^ (int(last7,2) & int(num[i:i+7],2)))[-7:]
        zz = xor4 + zz
        last7 = zz[i:i+7]
        i = i - 7
    first4 = z[:4]
    temp = first4 + zz
    xor5 = '{0:0>32b}'.format(int(first4,2) ^ (int(temp[7:11],2) & int(num[:4],2)))[-4:]
    zz = xor5 + zz

    # Undo Step 1 
    num = '{0:0>32b}'.format(0xFFFFFFFF)
    first11 = zz[:11]
    next11 = zz[11:22]
    xor6 = '{0:0>32b}'.format(int(next11,2) ^ (int(first11,2) & int(num[11:22],2)))[-11:]
    first10 = xor6[:10]
    next10 = zz[22:32]
    xor7 = '{0:0>32b}'.format(int(next10,2) ^ (int(first10,2) & int(num[22:32],2)))[-10:]
    zz = first11 + xor6 + xor7
    return int(zz,2)
        
def predict_RNG(s):
    mt = MT()
    mt.seed_mt(s)
    outputs = []
    seeds = []
    for i in range(624):
        output = mt.extract_number()
        outputs.append(output)
        newseed = untemper(output)
        seeds.append(newseed)
    print(outputs[0])

    mt2 = MT()
    mt2.index = 0
    mt2.state = seeds
    outputs2 = []
    for i in range(624):
        output = mt2.extract_number()
        outputs2.append(output)
    print(outputs2[2])


    # twobytes = genBytes(2)
# print(twobytes)

def encrypt_mt(textbytes):
    seed16bit = int.from_bytes(twobytes,byteorder='big')
    mt = MT()
    mt.seed_mt(seed16bit)
    keystream = b''
    while len(keystream) < len(textbytes):
        output = mt.extract_number()
        bitstr = '{0:0>32b}'.format(output)
        for i in range(0,len(bitstr),8):
            if len(keystream) >= len(textbytes):
                break
            keystream += bytes([int(bitstr[i:i+8],2)])
    crypto = crypt_xor(textbytes,keystream)
    return crypto

def decrypt_mt(cryptbytes):
    seed16bit = int.from_bytes(twobytes,byteorder='big')
    mt = MT()
    mt.seed_mt(seed16bit)
    keystream = b''
    while len(keystream) < len(cryptbytes):
        output = mt.extract_number()
        bitstr = '{0:0>32b}'.format(output)
        for i in range(0,len(bitstr),8):
            if len(keystream) >= len(cryptbytes):
                break
            keystream += bytes([int(bitstr[i:i+8],2)])
    textbytes = crypt_xor(cryptbytes,keystream)
    return textbytes
        
    
def crack_mt(cryptbytes):
    found = False
    mt = MT()
    for seed in range(2**16):
        mt.seed_mt(seed)
        keystream = b''
        while len(keystream) < len(cryptbytes):
            output = mt.extract_number()
            bitstr = '{0:0>32b}'.format(output)
            for i in range(0,len(bitstr),8):
                if len(keystream) >= len(cryptbytes):
                    break
                keystream += bytes([int(bitstr[i:i+8],2)])
        textbytes = crypt_xor(cryptbytes,keystream)
        if encrypt_mt(textbytes) == cryptbytes:
            found = True
            break
    if found: 
        bitstr = '{0:0>16b}'.format(seed)
        bites = b''.join([bytes([int(bitstr[i:i+8],2)]) for i in range(0,len(bitstr),8)])
        return bites
    else:
        return found

def password_reset():
    timestamp = int(time.time())
    mt = MT()
    mt.seed_mt(timestamp)
    token = mt.extract_number()
    return token
    

def validate_token(token):
    # specific time as input? Validating same time of token creation?
    t = int(time.time())
    mt = MT()
#     while t > #some number:
    while True:
        mt.seed_mt(t)
        token2 = mt.extract_number()
        if token == token2:
            return True
        t -= 1
    return False


### CHALLENGE 25 ### 
keybytes = genBytes(16)

def break_randaccess():
    with open('C:/Users/Zachary/Desktop/challenge25.txt') as file:
        reader = file.readlines()
        items = list(reader)
    for idx, item in enumerate(items):
        items[idx] = bytes(item[:-1],encoding='utf-8')
    textbytes = b''.join(items)
    crypto = encrypt_ctr(textbytes,keybytes,0)
    newbytes = genBytes(4)
    offset = randint(0,len(crypto)-len(newbytes)-1)
    newcrypto = edit(crypto, offset, newbytes)
    wrongbytes = decrypt_ctr(newcrypto,keybytes,0)
    print(wrongbytes)
    xor = crypt_xor(crypto,newcrypto)
    recovered = crypt_xor(xor,wrongbytes)
    return recovered
    
def edit(cryptbytes, offset, newbytes):
    textbytes = decrypt_ctr(cryptbytes,keybytes,0)
    _textbytes = textbytes[:offset] + newbytes + textbytes[offset+len(newbytes):]
    newcrypto = encrypt_ctr(_textbytes,keybytes,0)
    return newcrypto


### Challenge 26 ###
def changeCrypto2(crypbytes, offset):
    insert = b';admin=true;'
    blocksize = len(keybytes)
    textbytes = decrypt_ctr(crypbytes,keybytes,0)
    crypto = encrypt_ctr(textbytes,keybytes,0)
    xorbytes = textbytes[:offset] + insert + textbytes[offset+len(insert):]
    xor = crypt_xor(textbytes,xorbytes)
    newcrypto = crypt_xor(crypto,xor)
    newbytes = decrypt_ctr(newcrypto,keybytes,0)
    return newbytes

### CHALLENGE 27 ###
def encrypt_cbc_keyIV(textbytes,keybytes):
    
    cryptbytes = b''
    
    iv = keybytes
    blocksize = len(iv)
    
    for i in range(0,len(textbytes), blocksize):
        chunk = textbytes[i:i+blocksize]
        if len(chunk) < blocksize:
            chunk = pkcs7(chunk,blocksize)
        cryptchunk = encrypt_ecb(crypt_xor(chunk,iv),keybytes)
        cryptbytes += cryptchunk 
        iv = cryptchunk
    return cryptbytes

def decrypt_cbc_keyIV(cryptbytes,keybytes):
    
    plainbytes = []
    
    iv = keybytes
    blocksize = len(iv)
    
    for j in range(0,len(cryptbytes),blocksize):
        cryptchunk = cryptbytes[j:j+blocksize]
        chunk = crypt_xor(decrypt_ecb(cryptchunk,keybytes),iv) ## reverse reverse 
        # Check if padding valid 
        if chunk != unpad(chunk):
            valid_padding = True
        else:
            valid_padding = False
        chunk = unpad(chunk)
        plainbytes.append(chunk)
        iv = cryptchunk
    return b''.join(plainbytes), valid_padding 

def modify_cbc(cryptbytes):
    blocksize = 16
    cryptblocks = [cryptbytes[i:i+blocksize] for i in range(0,len(cryptbytes),blocksize)]
    newbytes = b''
    for idx, block in enumerate(cryptblocks):
        if idx == 1:
            newbytes += bytes([0]*blocksize)
        elif idx == 2:
            newbytes += cryptblocks[0]
        else:
            newbytes += block
    return newbytes

def find_key(cryptbytes):
    blocksize = 16
    newcrypto = modify_cbc(cryptbytes)
    newbytes, _ = decrypt_cbc_keyIV(newcrypto,b'YELLOW SUBMARINE')
    newblocks  = [newbytes[i:i+blocksize] for i in range(0,len(newbytes),blocksize)]
    key = crypt_xor(newblocks[0], newblocks[2])
    return key

### Challenge 28 ###

def sha1(textbytes, registers=None, length=None):
    if registers:
        h0 = registers[0]
        h1 = registers[1]
        h2 = registers[2]
        h3 = registers[3]
        h4 = registers[4]
        
    else:  
        h0 = 0x67452301
        h1 = 0xEFCDAB89
        h2 = 0x98BADCFE
        h3 = 0x10325476
        h4 = 0xC3D2E1F0
    
    def rol(n, b):
        return ((n << b) | (n >> (32 - b))) & 0xffffffff
    
    textbytes = [byte for byte in textbytes]
    bitstr = ''
    for byte in textbytes:
        bitstr += '{0:0>8b}'.format(byte)
    bitstr += '1'
    if length is None:
        length = len(bitstr)
        
        
    while len(bitstr) % 512 != 448:
        bitstr += '0'
    bitstr += '{0:0>64b}'.format(length-1)
    
    chunks = [bitstr[i:i+512] for i in range(0,len(bitstr),512)]
    for c in chunks:
        words = [c[i:i+32] for i in range(0,len(c),32)]
        w = [0] * 80
        for n in range(0,16):
            w[n] = int(words[n],2)
        for i in range(16,80):
            w[i] = rol((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1)
            
    a = h0
    b = h1
    c = h2
    d = h3
    e = h4
    
    for i in range(0,80):
        if 0 <= i <= 19:
            f = (b & c) | ((~b) & d)
            k = 0x5A827999
        elif 20 <= i <= 39:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif 40 <= i <= 59:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        elif 60 <= i <= 79:
            f = b ^ c ^ d
            k = 0xCA62C1D6
        
        temp = rol(a,5) + f + e + k + w[i] & 0xffffffff
        e = d
        d = c
        c = rol(b, 30)
        b = a
        a = temp
        
    h0 = h0 + a & 0xffffffff
    h1 = h1 + b & 0xffffffff
    h2 = h2 + c & 0xffffffff
    h3 = h3 + d & 0xffffffff
    h4 = h4 + e & 0xffffffff
    
    return (h0, h1, h2, h3, h4)

key = b'jinx'
def sha1_mac(message,registers=None):
    concat = key + message
    mac = sha1(concat,registers)
    print('%08x%08x%08x%08x%08x' % mac)
    return mac

def gluepad(textbytes):
    length = len(textbytes) * 8
    textbytes += b'\x80'
    textbytes += b'\x00' * ((56 - (len(textbytes) % 64)) % 64)
    textbytes += struct.pack('>Q', length)
    return textbytes
        

def break_mac(message, new_message):
    mac = sha1_mac(message)
#     print(len(mac))
#     bitstr = ''
#     for byte in mac:
#         bitstr += '{0:0>8b}'.format(byte)
#     bitblocks = [bitstr[i:i+8] for i in range(0,len(bitstr),8)]
#     print(len(bitstr),len(bitblocks))
#     macbytes = b''
#     for block in bitblocks:
#         macbytes += bytes([int(block,2)])

    registers = [reg for reg in mac]
    padmessage = gluepad(key + message)
    concat = padmessage + new_message
    length = len(concat) * 8
    forgedmessage = concat[len(key):]
    forgemac = sha1(new_message,registers,length)
    return forgedmessage, forgemac
    
        
    
    
    

    
    
                    
        