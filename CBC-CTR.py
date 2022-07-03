import secrets
import sys

''' GENERAL FUNCTIONS '''

def convert_to_hex(str): # convert ascii string into hexadecimal
    hex_str = "".join(format(ord(c), "x") for c in str)
    return hex_str

def convert_to_str(hex): # convert hexadecimal string into ascii
    bytes_object = bytes.fromhex(hex)
    str = bytes_object.decode("ASCII")
    return str

def hex_to_bin(hex): # convert hexadecimal byte into binary
    return bin(int(hex, 16))[2:].zfill(8) #zfill ensures that leading zeroes are kept in output

def bin_to_hex(bin): # convert binary string byte into hex
    return hex(int(bin, 2))[2:].zfill(2)

def left_shift(bin): # left shifts a binary string
    bin = bin[1:]
    bin += '0'
    return bin

def hex_inc(str): # increments a 64-bit hex string by one
    if (str == "ffffffffffffffff"): return "0000000000000000"
    return hex(int(str, 16) + 1)[2:].zfill(16)

def strxor(a, b): # xor two strings of different lengths
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

def hexxor(a, b): # xor two hex strings of different lengths
    if len(a) > len(b):
        return (hex(int(a, 16) ^ int(b, 16))[2:]).zfill(len(a))
    else:
        return (hex(int(a, 16) ^ int(b, 16))[2:]).zfill(len(b))

def binxor(a, b): # xor two binary strings
    return (bin(int(a,2) ^ int(b,2)))[2:].zfill(8)

def fill_array(s): # turns an 16 byte input string into a 4x4 array of bytes
    if len(s) < 32:
        print("WARNING: LENGTH OF STR IS: " + str(len(s)))
        s = s.zfill(32)
        print("STRING IS NOW: " + s)
    arr = []
    for i in range(0, 8, 2):
        byte = ""
        sub_arr = []
        for j in range(0, len(s), 8):
            byte += s[i+j]
            byte += s[i+1+j]
            sub_arr.append(byte)
            byte = ""
        arr.append(sub_arr)
    return arr

def crypto_mult_by_2(binary_num): # multiples by 2 in GF(2^8)
    firstBitIsOne = False
    if binary_num[0] == '1':
        firstBitIsOne = True
    binary_num = left_shift(binary_num)
    if firstBitIsOne:
        binary_num = binxor(binary_num, '00011011')
    return binary_num

''' AES KEY-SCHEDULER HELPER FUNCTIONS '''

def AES_KS_ROTWORD(word):   # right shifts word
    toMove = word[0]
    word.pop(0)
    word.append(toMove)
    return word

def AES_KS_SBOX(byte):      # applies the AES S-Box to input byte
    if byte == '00': return '63'
    if byte == '01': return '7c'
    if byte == '02': return '77'
    if byte == '03': return '7b'
    if byte == '04': return 'f2'
    if byte == '05': return '6b'
    if byte == '06': return '6f'
    if byte == '07': return 'c5'
    if byte == '08': return '30'
    if byte == '09': return '01'
    if byte == '0a': return '67'
    if byte == '0b': return '2b'
    if byte == '0c': return 'fe'
    if byte == '0d': return 'd7'
    if byte == '0e': return 'ab'
    if byte == '0f': return '76'

    if byte == '10': return 'ca'
    if byte == '11': return '82'
    if byte == '12': return 'c9'
    if byte == '13': return '7d'
    if byte == '14': return 'fa'
    if byte == '15': return '59'
    if byte == '16': return '47'
    if byte == '17': return 'f0'
    if byte == '18': return 'ad'
    if byte == '19': return 'd4'
    if byte == '1a': return 'a2'
    if byte == '1b': return 'af'
    if byte == '1c': return '9c'
    if byte == '1d': return 'a4'
    if byte == '1e': return '72'
    if byte == '1f': return 'c0'

    if byte == '20': return 'b7'
    if byte == '21': return 'fd'
    if byte == '22': return '93'
    if byte == '23': return '26'
    if byte == '24': return '36'
    if byte == '25': return '3f'
    if byte == '26': return 'f7'
    if byte == '27': return 'cc'
    if byte == '28': return '34'
    if byte == '29': return 'a5'
    if byte == '2a': return 'e5'
    if byte == '2b': return 'f1'
    if byte == '2c': return '71'
    if byte == '2d': return 'd8'
    if byte == '2e': return '31'
    if byte == '2f': return '15'

    if byte == '30': return '04'
    if byte == '31': return 'c7'
    if byte == '32': return '23'
    if byte == '33': return 'c3'
    if byte == '34': return '18'
    if byte == '35': return '96'
    if byte == '36': return '05'
    if byte == '37': return '9a'
    if byte == '38': return '07'
    if byte == '39': return '12'
    if byte == '3a': return '80'
    if byte == '3b': return 'e2'
    if byte == '3c': return 'eb'
    if byte == '3d': return '27'
    if byte == '3e': return 'b2'
    if byte == '3f': return '75'

    if byte == '40': return '09'
    if byte == '41': return '83'
    if byte == '42': return '2c'
    if byte == '43': return '1a'
    if byte == '44': return '1b'
    if byte == '45': return '6e'
    if byte == '46': return '5a'
    if byte == '47': return 'a0'
    if byte == '48': return '52'
    if byte == '49': return '3b'
    if byte == '4a': return 'd6'
    if byte == '4b': return 'b3'
    if byte == '4c': return '29'
    if byte == '4d': return 'e3'
    if byte == '4e': return '2f'
    if byte == '4f': return '84'

    if byte == '50': return '53'
    if byte == '51': return 'd1'
    if byte == '52': return '00'
    if byte == '53': return 'ed'
    if byte == '54': return '20'
    if byte == '55': return 'fc'
    if byte == '56': return 'b1'
    if byte == '57': return '5b'
    if byte == '58': return '6a'
    if byte == '59': return 'cb'
    if byte == '5a': return 'be'
    if byte == '5b': return '39'
    if byte == '5c': return '4a'
    if byte == '5d': return '4c'
    if byte == '5e': return '58'
    if byte == '5f': return 'cf'

    if byte == '60': return 'd0'
    if byte == '61': return 'ef'
    if byte == '62': return 'aa'
    if byte == '63': return 'fb'
    if byte == '64': return '43'
    if byte == '65': return '4d'
    if byte == '66': return '33'
    if byte == '67': return '85'
    if byte == '68': return '45'
    if byte == '69': return 'f9'
    if byte == '6a': return '02'
    if byte == '6b': return '7f'
    if byte == '6c': return '50'
    if byte == '6d': return '3c'
    if byte == '6e': return '9f'
    if byte == '6f': return 'a8'

    if byte == '70': return '51'
    if byte == '71': return 'a3'
    if byte == '72': return '40'
    if byte == '73': return '8f'
    if byte == '74': return '92'
    if byte == '75': return '9d'
    if byte == '76': return '38'
    if byte == '77': return 'f5'
    if byte == '78': return 'bc'
    if byte == '79': return 'b6'
    if byte == '7a': return 'da'
    if byte == '7b': return '21'
    if byte == '7c': return '10'
    if byte == '7d': return 'ff'
    if byte == '7e': return 'f3'
    if byte == '7f': return 'd2'

    if byte == '80': return 'cd'
    if byte == '81': return '0c'
    if byte == '82': return '13'
    if byte == '83': return 'ec'
    if byte == '84': return '5f'
    if byte == '85': return '97'
    if byte == '86': return '44'
    if byte == '87': return '17'
    if byte == '88': return 'c4'
    if byte == '89': return 'a7'
    if byte == '8a': return '7e'
    if byte == '8b': return '3d'
    if byte == '8c': return '64'
    if byte == '8d': return '5d'
    if byte == '8e': return '19'
    if byte == '8f': return '73'

    if byte == '90': return '60'
    if byte == '91': return '81'
    if byte == '92': return '4f'
    if byte == '93': return 'dc'
    if byte == '94': return '22'
    if byte == '95': return '2a'
    if byte == '96': return '90'
    if byte == '97': return '88'
    if byte == '98': return '46'
    if byte == '99': return 'ee'
    if byte == '9a': return 'b8'
    if byte == '9b': return '14'
    if byte == '9c': return 'de'
    if byte == '9d': return '5e'
    if byte == '9e': return '0b'
    if byte == '9f': return 'db'

    if byte == 'a0': return 'e0'
    if byte == 'a1': return '32'
    if byte == 'a2': return '3a'
    if byte == 'a3': return '0a'
    if byte == 'a4': return '49'
    if byte == 'a5': return '06'
    if byte == 'a6': return '24'
    if byte == 'a7': return '5c'
    if byte == 'a8': return 'c2'
    if byte == 'a9': return 'd3'
    if byte == 'aa': return 'ac'
    if byte == 'ab': return '62'
    if byte == 'ac': return '91'
    if byte == 'ad': return '95'
    if byte == 'ae': return 'e4'
    if byte == 'af': return '79'

    if byte == 'b0': return 'e7'
    if byte == 'b1': return 'c8'
    if byte == 'b2': return '37'
    if byte == 'b3': return '6d'
    if byte == 'b4': return '8d'
    if byte == 'b5': return 'd5'
    if byte == 'b6': return '4e'
    if byte == 'b7': return 'a9'
    if byte == 'b8': return '6c'
    if byte == 'b9': return '56'
    if byte == 'ba': return 'f4'
    if byte == 'bb': return 'ea'
    if byte == 'bc': return '65'
    if byte == 'bd': return '7a'
    if byte == 'be': return 'ae'
    if byte == 'bf': return '08'

    if byte == 'c0': return 'ba'
    if byte == 'c1': return '78'
    if byte == 'c2': return '25'
    if byte == 'c3': return '2e'
    if byte == 'c4': return '1c'
    if byte == 'c5': return 'a6'
    if byte == 'c6': return 'b4'
    if byte == 'c7': return 'c6'
    if byte == 'c8': return 'e8'
    if byte == 'c9': return 'dd'
    if byte == 'ca': return '74'
    if byte == 'cb': return '1f'
    if byte == 'cc': return '4b'
    if byte == 'cd': return 'bd'
    if byte == 'ce': return '8b'
    if byte == 'cf': return '8a'

    if byte == 'd0': return '70'
    if byte == 'd1': return '3e'
    if byte == 'd2': return 'b5'
    if byte == 'd3': return '66'
    if byte == 'd4': return '48'
    if byte == 'd5': return '03'
    if byte == 'd6': return 'f6'
    if byte == 'd7': return '0e'
    if byte == 'd8': return '61'
    if byte == 'd9': return '35'
    if byte == 'da': return '57'
    if byte == 'db': return 'b9'
    if byte == 'dc': return '86'
    if byte == 'dd': return 'c1'
    if byte == 'de': return '1d'
    if byte == 'df': return '9e'

    if byte == 'e0': return 'e1'
    if byte == 'e1': return 'f8'
    if byte == 'e2': return '98'
    if byte == 'e3': return '11'
    if byte == 'e4': return '69'
    if byte == 'e5': return 'd9'
    if byte == 'e6': return '8e'
    if byte == 'e7': return '94'
    if byte == 'e8': return '9b'
    if byte == 'e9': return '1e'
    if byte == 'ea': return '87'
    if byte == 'eb': return 'e9'
    if byte == 'ec': return 'ce'
    if byte == 'ed': return '55'
    if byte == 'ee': return '28'
    if byte == 'ef': return 'df'

    if byte == 'f0': return '8c'
    if byte == 'f1': return 'a1'
    if byte == 'f2': return '89'
    if byte == 'f3': return '0d'
    if byte == 'f4': return 'bf'
    if byte == 'f5': return 'e6'
    if byte == 'f6': return '42'
    if byte == 'f7': return '68'
    if byte == 'f8': return '41'
    if byte == 'f9': return '99'
    if byte == 'fa': return '2d'
    if byte == 'fb': return '0f'
    if byte == 'fc': return 'b0'
    if byte == 'fd': return '54'
    if byte == 'fe': return 'bb'
    if byte == 'ff': return '16'

def AES_KS_INV_SBOX(byte):      # applies the inverse of the AES S-Box for decryption
    if byte == '00': return '52'
    if byte == '01': return '09'
    if byte == '02': return '6a'
    if byte == '03': return 'd5'
    if byte == '04': return '30'
    if byte == '05': return '36'
    if byte == '06': return 'a5'
    if byte == '07': return '38'
    if byte == '08': return 'bf'
    if byte == '09': return '40'
    if byte == '0a': return 'a3'
    if byte == '0b': return '9e'
    if byte == '0c': return '81'
    if byte == '0d': return 'f3'
    if byte == '0e': return 'd7'
    if byte == '0f': return 'fb'

    if byte == '10': return '7c'
    if byte == '11': return 'e3'
    if byte == '12': return '39'
    if byte == '13': return '82'
    if byte == '14': return '9b'
    if byte == '15': return '2f'
    if byte == '16': return 'ff'
    if byte == '17': return '87'
    if byte == '18': return '34'
    if byte == '19': return '8e'
    if byte == '1a': return '43'
    if byte == '1b': return '44'
    if byte == '1c': return 'c4'
    if byte == '1d': return 'de'
    if byte == '1e': return 'e9'
    if byte == '1f': return 'cb'

    if byte == '20': return '54'
    if byte == '21': return '7b'
    if byte == '22': return '94'
    if byte == '23': return '32'
    if byte == '24': return 'a6'
    if byte == '25': return 'c2'
    if byte == '26': return '23'
    if byte == '27': return '3d'
    if byte == '28': return 'ee'
    if byte == '29': return '4c'
    if byte == '2a': return '95'
    if byte == '2b': return '0b'
    if byte == '2c': return '42'
    if byte == '2d': return 'fa'
    if byte == '2e': return 'c3'
    if byte == '2f': return '4e'

    if byte == '30': return '08'
    if byte == '31': return '2e'
    if byte == '32': return 'a1'
    if byte == '33': return '66'
    if byte == '34': return '28'
    if byte == '35': return 'd9'
    if byte == '36': return '24'
    if byte == '37': return 'b2'
    if byte == '38': return '76'
    if byte == '39': return '5b'
    if byte == '3a': return 'a2'
    if byte == '3b': return '49'
    if byte == '3c': return '6d'
    if byte == '3d': return '8b'
    if byte == '3e': return 'd1'
    if byte == '3f': return '25'

    if byte == '40': return '72'
    if byte == '41': return 'f8'
    if byte == '42': return 'f6'
    if byte == '43': return '64'
    if byte == '44': return '86'
    if byte == '45': return '68'
    if byte == '46': return '98'
    if byte == '47': return '16'
    if byte == '48': return 'd4'
    if byte == '49': return 'a4'
    if byte == '4a': return '5c'
    if byte == '4b': return 'cc'
    if byte == '4c': return '5d'
    if byte == '4d': return '65'
    if byte == '4e': return 'b6'
    if byte == '4f': return '92'

    if byte == '50': return '6c'
    if byte == '51': return '70'
    if byte == '52': return '48'
    if byte == '53': return '50'
    if byte == '54': return 'fd'
    if byte == '55': return 'ed'
    if byte == '56': return 'b9'
    if byte == '57': return 'da'
    if byte == '58': return '5e'
    if byte == '59': return '15'
    if byte == '5a': return '46'
    if byte == '5b': return '57'
    if byte == '5c': return 'a7'
    if byte == '5d': return '8d'
    if byte == '5e': return '9d'
    if byte == '5f': return '84'

    if byte == '60': return '90'
    if byte == '61': return 'd8'
    if byte == '62': return 'ab'
    if byte == '63': return '00'
    if byte == '64': return '8c'
    if byte == '65': return 'bc'
    if byte == '66': return 'd3'
    if byte == '67': return '0a'
    if byte == '68': return 'f7'
    if byte == '69': return 'e4'
    if byte == '6a': return '58'
    if byte == '6b': return '05'
    if byte == '6c': return 'b8'
    if byte == '6d': return 'b3'
    if byte == '6e': return '45'
    if byte == '6f': return '06'

    if byte == '70': return 'd0'
    if byte == '71': return '2c'
    if byte == '72': return '1e'
    if byte == '73': return '8f'
    if byte == '74': return 'ca'
    if byte == '75': return '3f'
    if byte == '76': return '0f'
    if byte == '77': return '02'
    if byte == '78': return 'c1'
    if byte == '79': return 'af'
    if byte == '7a': return 'bd'
    if byte == '7b': return '03'
    if byte == '7c': return '01'
    if byte == '7d': return '13'
    if byte == '7e': return '8a'
    if byte == '7f': return '6b'

    if byte == '80': return '3a'
    if byte == '81': return '91'
    if byte == '82': return '11'
    if byte == '83': return '41'
    if byte == '84': return '4f'
    if byte == '85': return '67'
    if byte == '86': return 'dc'
    if byte == '87': return 'ea'
    if byte == '88': return '97'
    if byte == '89': return 'f2'
    if byte == '8a': return 'cf'
    if byte == '8b': return 'ce'
    if byte == '8c': return 'f0'
    if byte == '8d': return 'b4'
    if byte == '8e': return 'e6'
    if byte == '8f': return '73'

    if byte == '90': return '96'
    if byte == '91': return 'ac'
    if byte == '92': return '74'
    if byte == '93': return '22'
    if byte == '94': return 'e7'
    if byte == '95': return 'ad'
    if byte == '96': return '35'
    if byte == '97': return '85'
    if byte == '98': return 'e2'
    if byte == '99': return 'f9'
    if byte == '9a': return '37'
    if byte == '9b': return 'e8'
    if byte == '9c': return '1c'
    if byte == '9d': return '75'
    if byte == '9e': return 'df'
    if byte == '9f': return '6e'

    if byte == 'a0': return '47'
    if byte == 'a1': return 'f1'
    if byte == 'a2': return '1a'
    if byte == 'a3': return '71'
    if byte == 'a4': return '1d'
    if byte == 'a5': return '29'
    if byte == 'a6': return 'c5'
    if byte == 'a7': return '89'
    if byte == 'a8': return '6f'
    if byte == 'a9': return 'b7'
    if byte == 'aa': return '62'
    if byte == 'ab': return '0e'
    if byte == 'ac': return 'aa'
    if byte == 'ad': return '18'
    if byte == 'ae': return 'be'
    if byte == 'af': return '1b'

    if byte == 'b0': return 'fc'
    if byte == 'b1': return '56'
    if byte == 'b2': return '3e'
    if byte == 'b3': return '4b'
    if byte == 'b4': return 'c6'
    if byte == 'b5': return 'd2'
    if byte == 'b6': return '79'
    if byte == 'b7': return '20'
    if byte == 'b8': return '9a'
    if byte == 'b9': return 'db'
    if byte == 'ba': return 'c0'
    if byte == 'bb': return 'fe'
    if byte == 'bc': return '78'
    if byte == 'bd': return 'cd'
    if byte == 'be': return '5a'
    if byte == 'bf': return 'f4'

    if byte == 'c0': return '1f'
    if byte == 'c1': return 'dd'
    if byte == 'c2': return 'a8'
    if byte == 'c3': return '33'
    if byte == 'c4': return '88'
    if byte == 'c5': return '07'
    if byte == 'c6': return 'c7'
    if byte == 'c7': return '31'
    if byte == 'c8': return 'b1'
    if byte == 'c9': return '12'
    if byte == 'ca': return '10'
    if byte == 'cb': return '59'
    if byte == 'cc': return '27'
    if byte == 'cd': return '80'
    if byte == 'ce': return 'ec'
    if byte == 'cf': return '5f'

    if byte == 'd0': return '60'
    if byte == 'd1': return '51'
    if byte == 'd2': return '7f'
    if byte == 'd3': return 'a9'
    if byte == 'd4': return '19'
    if byte == 'd5': return 'b5'
    if byte == 'd6': return '4a'
    if byte == 'd7': return '0d'
    if byte == 'd8': return '2d'
    if byte == 'd9': return 'e5'
    if byte == 'da': return '7a'
    if byte == 'db': return '9f'
    if byte == 'dc': return '93'
    if byte == 'dd': return 'c9'
    if byte == 'de': return '9c'
    if byte == 'df': return 'ef'

    if byte == 'e0': return 'a0'
    if byte == 'e1': return 'e0'
    if byte == 'e2': return '3b'
    if byte == 'e3': return '4d'
    if byte == 'e4': return 'ae'
    if byte == 'e5': return '2a'
    if byte == 'e6': return 'f5'
    if byte == 'e7': return 'b0'
    if byte == 'e8': return 'c8'
    if byte == 'e9': return 'eb'
    if byte == 'ea': return 'bb'
    if byte == 'eb': return '3c'
    if byte == 'ec': return '83'
    if byte == 'ed': return '53'
    if byte == 'ee': return '99'
    if byte == 'ef': return '61'

    if byte == 'f0': return '17'
    if byte == 'f1': return '2b'
    if byte == 'f2': return '04'
    if byte == 'f3': return '7e'
    if byte == 'f4': return 'ba'
    if byte == 'f5': return '77'
    if byte == 'f6': return 'd6'
    if byte == 'f7': return '26'
    if byte == 'f8': return 'e1'
    if byte == 'f9': return '69'
    if byte == 'fa': return '14'
    if byte == 'fb': return '63'
    if byte == 'fc': return '55'
    if byte == 'fd': return '21'
    if byte == 'fe': return '0c'
    if byte == 'ff': return '7d'

def AES_KS_SUBWORD(word):   # applies s-box to each byte of input word
    for byte in range(len(word)):
        word[byte] = AES_KS_SBOX(word[byte])
    return word

def AES_KS_INV_SUBWORD(word):   # applies inverse s-box to each byte of input word
    for byte in range(len(word)):
        word[byte] = AES_KS_INV_SBOX(word[byte])
    return word

def AES_KS_RCON(i, word):      # returns 4-byte word depending on the round #
    returnWord = ""
    for char in word:
        returnWord += char
    if i == 1: return hexxor(returnWord, '01000000')
    if i == 2: return hexxor(returnWord, '02000000')
    if i == 3: return hexxor(returnWord, '04000000')
    if i == 4: return hexxor(returnWord, '08000000')
    if i == 5: return hexxor(returnWord, '10000000')
    if i == 6: return hexxor(returnWord, '20000000')
    if i == 7: return hexxor(returnWord, '40000000')
    if i == 8: return hexxor(returnWord, '80000000')
    if i == 9: return hexxor(returnWord, '1b000000')
    if i == 10:return hexxor(returnWord, '36000000')



''' AES KEY-SCHEDULER'''

def AES_KS(key):
    temp_key = []
    new_key = []
    round_keys = [key] # array of expanded round keys which will be returned

    for i in range(0, len(key), 8): # turns initial key into an array of 4-byte words
        temp_key.append(key[i:i+8])

    for i in range(10):
        w3 = temp_key[3] # selects ending 4 byte word of previous key for manipulation
        w3_arr = [w3[i:i+2] for i in range(0, len(w3), 2)] # turns this 4 byte word into an array of 1-byte subwords for byte by byte manipulation
        tempWord = AES_KS_RCON(i + 1, AES_KS_SUBWORD(AES_KS_ROTWORD(w3_arr))) # applies word rotation, subword, and round control to each byte of w3
        new_key.append(hexxor(temp_key[0], tempWord))
        new_key.append(hexxor(temp_key[1], new_key[0]))
        new_key.append(hexxor(temp_key[2], new_key[1]))
        new_key.append(hexxor(temp_key[3], new_key[2]))
        round_keys.append(new_key[0] + new_key[1] + new_key[2] + new_key[3]) # adds new key to the array of expanded keys
        temp_key = new_key # sets the previous key to be the new key for next iteration
        new_key = [] # resets new key

    return round_keys



''' AES HELPER FUNCTIONS'''

def AES_HF_SHIFTROWS(aes_state): # applies cyclical rotation of bytes based on AES specification
    # shift second row left by 1 byte
    toMove = aes_state[1][0]
    aes_state[1].pop(0)
    aes_state[1].append(toMove)

    # shift third row left by 2 bytes
    toMove = aes_state[2][0]
    aes_state[2].pop(0)
    aes_state[2].append(toMove)
    toMove = aes_state[2][0]
    aes_state[2].pop(0)
    aes_state[2].append(toMove)

    # shift fourth row left by 3 bytes
    toMove = aes_state[3][0]
    aes_state[3].pop(0)
    aes_state[3].append(toMove)
    toMove = aes_state[3][0]
    aes_state[3].pop(0)
    aes_state[3].append(toMove)
    toMove = aes_state[3][0]
    aes_state[3].pop(0)
    aes_state[3].append(toMove)


def AES_HF_INV_SHIFTROWS(aes_state): # inverse of shift rows function used for decryption
    # shift second row right by 1 byte
    toMove = aes_state[1][3]
    aes_state[1].pop(3)
    aes_state[1].insert(0, toMove)

    # shift third row right by 2 bytes
    toMove = aes_state[2][3]
    aes_state[2].pop(3)
    aes_state[2].insert(0, toMove)
    toMove = aes_state[2][3]
    aes_state[2].pop(3)
    aes_state[2].insert(0, toMove)

    # shift fourth row right by 3 bytes
    toMove = aes_state[3][3]
    aes_state[3].pop(3)
    aes_state[3].insert(0, toMove)
    toMove = aes_state[3][3]
    aes_state[3].pop(3)
    aes_state[3].insert(0, toMove)
    toMove = aes_state[3][3]
    aes_state[3].pop(3)
    aes_state[3].insert(0, toMove)


def AES_HF_MIXCOL(col): # MixColumn function
    #  matrix used for multiplying the col
    binary_matrix = [
        ['00000010', '00000011', '00000001', '00000001'],
        ['00000001', '00000010', '00000011', '00000001'],
        ['00000001', '00000001', '00000010', '00000011'],
        ['00000011', '00000001', '00000001', '00000010']
    ]

    # initial vals
    returnCol = []
    val = '00000000'
    vals = []
    firstBitIsOne = False

    # multiplying the column by the above matrix
    for i in range(len(binary_matrix)):
        for j in range(len(binary_matrix[i])):
            binary_col = hex_to_bin(col[j])
            if binary_col[0] == '1':
                firstBitIsOne = True

            if (binary_matrix[i][j] == '00000001'): # we are multypling by one
                vals.append(binary_col)

            elif (binary_matrix[i][j] == '00000010'): # we are multypling by two
                binary_col = left_shift(binary_col)
                if firstBitIsOne:
                    binary_col = binxor(binary_col, '00011011')
                vals.append(binary_col)


            else: # we are multypling by three
                temp = binary_col
                binary_col = left_shift(binary_col)
                if firstBitIsOne:
                    binary_col = binxor(binary_col, '00011011')
                vals.append(binxor(binary_col, temp))

            firstBitIsOne = False

        for v in vals:
            val = binxor(v, val)
        returnCol.append(bin_to_hex(val))
        val = '00000000'
        vals = []

    return returnCol


def AES_HF_INV_MIXCOL(col): # Inverse of the MixColumn function
    #  matrix used for multiplying the col
    binary_matrix = [
        ['00001110', '00001011', '00001101', '00001001'],
        ['00001001', '00001110', '00001011', '00001101'],
        ['00001101', '00001001', '00001110', '00001011'],
        ['00001011', '00001101', '00001001', '00001110']
    ]

    # initial vals
    returnCol = []
    val = '00000000'
    vals = []
    firstBitIsOne = False

    # multiplying the column by the above matrix
    for i in range(len(binary_matrix)):
        for j in range(len(binary_matrix[i])):
            binary_col = hex_to_bin(col[j])
            if binary_col[0] == '1':
                firstBitIsOne = True

            if (binary_matrix[i][j] == '00001001'): # we are multypling by 9
                binary_col = binxor(crypto_mult_by_2(crypto_mult_by_2(crypto_mult_by_2(binary_col))) , binary_col)
                vals.append(binary_col)

            elif (binary_matrix[i][j] == '00001011'): # we are multypling by b
                binary_col = binxor(crypto_mult_by_2(binxor(crypto_mult_by_2(crypto_mult_by_2(binary_col)), binary_col)), binary_col)
                vals.append(binary_col)

            elif (binary_matrix[i][j] == '00001101'): # we are multypling by d
                binary_col = binxor(crypto_mult_by_2(crypto_mult_by_2(binxor(crypto_mult_by_2(binary_col), binary_col))), binary_col)
                vals.append(binary_col)

            else:                                      # we are multypling by e
                binary_col = crypto_mult_by_2(binxor(crypto_mult_by_2(binxor(crypto_mult_by_2(binary_col), binary_col)), binary_col))
                vals.append(binary_col)

            firstBitIsOne = False

        for v in vals:
            val = binxor(v, val)
        returnCol.append(bin_to_hex(val))
        val = '00000000'
        vals = []

    return returnCol


''' AES ENCRYPT & DECRYPT'''

def AES_ENCRYPT(key, input):        # implementation of AES which will be used in the cbc & ctr encryption systems below
    roundKeys = AES_KS(key)
    AES_STATE = fill_array(input) # initializes the 4x4 array to be used for the AES state

    for x in range(10):
        roundKey = fill_array(roundKeys[x]) # initializes the 4x4 array to be used for the round-keys
        for i in range(len(AES_STATE)):
            for j in range(len(AES_STATE[i])):
                    AES_STATE[i][j] = AES_KS_SBOX(hexxor(AES_STATE[i][j], roundKey[i][j])) # xors i,jth byte of state with round key then applies s-box

        AES_HF_SHIFTROWS(AES_STATE) # applies shiftrow function

        if(x < 9): # dont apply MixColumn function to 10th round
            for c in range(len(AES_STATE)):
                col = AES_HF_MIXCOL([AES_STATE[0][c], AES_STATE[1][c], AES_STATE[2][c], AES_STATE[3][c]]) # applies MixColumn function to cth column
                for b in range(4):
                    AES_STATE[b][c] = col[b]

    # xors 10th round key before getting the final output
    CT = ""
    roundKey = fill_array(roundKeys[10])
    for i in range(len(AES_STATE)):
        for j in range(len(AES_STATE[i])):
            AES_STATE[j][i] = hexxor(AES_STATE[j][i], roundKey[j][i])
            CT += AES_STATE[j][i]

    return CT

def AES_DECRYPT(key, cipher):
    roundKeys = AES_KS(key)
    AES_STATE = fill_array(cipher) # initializes the 4x4 array to be used for the AES state

    roundKey = fill_array(roundKeys[10])
    for i in range(len(AES_STATE)):
        for j in range(len(AES_STATE[i])):
            AES_STATE[j][i] = hexxor(AES_STATE[j][i], roundKey[j][i])

    for x in reversed(range(10)):
        AES_HF_INV_SHIFTROWS(AES_STATE) # applies inverse shiftrow function

        roundKey = fill_array(roundKeys[x]) # initializes the 4x4 array to be used for the round-keys
        for i in range(len(AES_STATE)):
            for j in range(len(AES_STATE[i])):
                    AES_STATE[i][j] = hexxor(AES_KS_INV_SBOX(AES_STATE[i][j]), roundKey[i][j]) # xors i,jth byte of state with round key then applies s-box

        if(x > 0): # dont apply MixColumn function to 10th round
            for c in range(len(AES_STATE)):
                col = AES_HF_INV_MIXCOL([AES_STATE[0][c], AES_STATE[1][c], AES_STATE[2][c], AES_STATE[3][c]]) # applies MixColumn function to cth column
                for b in range(4):
                    AES_STATE[b][c] = col[b]

    # xors 10th round key before getting the final output
    PT = ""
    for i in range(len(AES_STATE)):
        for j in range(len(AES_STATE[i])):
            PT += AES_STATE[j][i]

    return PT



def encrypt_cbc(key, msg):
    cipher = ""
    hex_msg = convert_to_hex(msg)

    # pad the message if not divisible by blocksize, otherwise add a dummy block
    padding = 16 - len(msg) % 16
    if padding != 0:
        for i in range(padding):
            hex_msg += '0'
            hex_msg += hex(padding)[3:]
    else:
        for i in range(16):
            hex_msg += '10'

    # create the initialization vector and make it the start of the ciphertext
    IV = secrets.token_hex(16)
    cipher += IV
    nextBlock = ""

    # the CBC encryption circuit using AES for the block cipher
    for i in range(0, len(hex_msg), 32):
        if i == 0:
            nextBlock = hexxor(IV, hex_msg[0:32])
            nextBlock = AES_ENCRYPT(key, nextBlock)
            cipher += nextBlock
        else:
            nextBlock = AES_ENCRYPT(key, hexxor(nextBlock, hex_msg[i:i+32]))
            cipher += nextBlock

    return cipher

def decrypt_cbc(key, ct):
    pt = ""
    IV = ct[0:32]
    nextBlock = ""
    padding = 0

    # the CBC decryption circuit using AES for the block cipher
    for i in range(32, len(ct), 32):

        if i == 32:
            nextBlock = ct[32:64]
            pt += convert_to_str(hexxor(IV, AES_DECRYPT(key, nextBlock)))
        else:
            prevBlock = nextBlock
            nextBlock = ct[i:i+32]
            pt += convert_to_str(hexxor(prevBlock, AES_DECRYPT(key, nextBlock)))

    pt = pt.rstrip(pt[len(pt) - 1])
    return pt



def encrypt_ctr(key, msg): # Counter mode encryption using the above implementation of AES
    cipher = ""
    hex_msg = convert_to_hex(msg)

    # create the initialization vector and make it the start of the ciphertext
    nonce = secrets.token_hex(16)
    cipher += nonce
    iter = 0

    # the encryption circuit
    for i in range(0, len(hex_msg), 32):
        iter = i
        if (i + 32 > len(hex_msg)):
            break
        cipher += hexxor(hex_msg[i:i+32], AES_ENCRYPT(key, nonce))
        nonce = hex_inc(nonce)

    # check for any remaining message syntax after each 128 bit block has been encrypted
    if (iter < len(hex_msg)):
        i = 0
        aes = AES_ENCRYPT(key, nonce)
        while (iter < len(hex_msg)):
            cipher += hexxor(hex_msg[iter:iter+1], aes[i:i+1])
            iter += 1
            i += 1

    return cipher

def decrypt_ctr(key, ct):
    pt = ""
    nonce = ct[0:32]

    # the decryption circuit
    for i in range(32, len(ct), 32):
        iter = i
        if (i + 32 > len(ct)):
            break
        pt += hexxor(ct[i:i+32], AES_ENCRYPT(key, nonce))
        nonce = hex_inc(nonce)

    # check for any remaining message syntax after each 128 bit block has been decrypted
    if (iter < len(ct)):
        i = 0
        aes = AES_ENCRYPT(key, nonce)
        while (iter < len(ct)):
            pt += hexxor(ct[iter:iter+2], aes[i:i+2])
            iter += 2
            i += 2

    return convert_to_str(pt)




def main():
    print()
    while True:
        print("Welcome to the block cipher encryption program, to continue, please select a mode of operation:")
        print("-------------------------------------------------------------------------------------------------")
        print("To encrypt a message using Cipher block chaining: please type '1'.")
        print("To encrypt a message using Randomized counter mode: please type '2'.")
        print("To exit, please type 'q'.")
        usr_input = input()
        print()


        if usr_input == '1': # CBC mode
            print("You have chosen CBC encryption mode.")
            while True:
                print("-------------------------------------------------------------")
                print("To encrypt a message using a randomized key: please type '1'.")
                print("To encrypt a message using a custom provided key: please type '2'.")
                print("To decrypt a (key, ciphertext) pair: please type '3'.")
                print("To go back, please type 'b'.")
                print("To exit, please type 'q'.")
                usr_input2 = input()
                print()

                if usr_input2 == '1':
                    print("You have selected encryption using a randomized key, please input your message below.")
                    print("message: ", end = '')
                    msg = input()
                    print()
                    key = secrets.token_hex(16)
                    print("Your randomly chosen key is: " + str(key))
                    print("Your ciphertext is: " + str(encrypt_cbc(key, msg)))
                    print()

                elif usr_input2 == '2':
                    print("You have selected encryption using a provided key, please input your message and key below.")
                    print("message: ", end = '')
                    msg = input()
                    print("key (in hex): ", end = '')
                    key = input()
                    print()
                    print("Your ciphertext is: " + str(encrypt_cbc(key, msg)))
                    print()

                elif usr_input2 == '3':
                    print("You have selected the decryption of a (key, ciphertext) pair, please input your ciphertext and key below.")
                    print("ciphertext (in hex): ", end = '')
                    ct = input()
                    print("key (in hex): ", end = '')
                    key = input()
                    print("\nYour secret message is: \"" + str(decrypt_cbc(key, ct)) + "\"")
                    print()

                elif usr_input2 == 'b':
                    break

                elif usr_input2 == 'q':
                    print("Exiting program")
                    return

                else:
                    print("Input not recognized, please try again.")
                    print()

        elif usr_input == '2': # CTR mode
            print("You have chosen CTR encryption mode.")
            while True:
                print("-------------------------------------------------------------")
                print("To encrypt a message using a randomized key: please type '1'.")
                print("To encrypt a message using a custom provided key: please type '2'.")
                print("To decrypt a (key, ciphertext) pair: please type '3'.")
                print("To go back, please type 'b'.")
                print("To exit, please type 'q'.")
                usr_input2 = input()
                print()

                if usr_input2 == '1':
                    print("You have selected encryption using a randomized key, please input your message below.")
                    print("message: ", end = '')
                    msg = input()
                    print()
                    key = secrets.token_hex(16)
                    print("Your randomly chosen key is: " + str(key))
                    print("Your ciphertext is: " + str(encrypt_ctr(key, msg)))
                    print()

                elif usr_input2 == '2':
                    print("You have selected encryption using a provided key, please input your message and key below.")
                    print("message: ", end = '')
                    msg = input()
                    print("key (in hex): ", end = '')
                    key = input()
                    print()
                    print("Your ciphertext is: " + str(encrypt_ctr(key, msg)))
                    print()

                elif usr_input2 == '3':
                    print("You have selected the decryption of a (key, ciphertext) pair, please input your ciphertext and key below.")
                    print("ciphertext (in hex): ", end = '')
                    ct = input()
                    print("key (in hex): ", end = '')
                    key = input()
                    print("\nYour secret message is: \"" + str(decrypt_ctr(key, ct)) + "\"")
                    print()

                elif usr_input2 == 'b':
                    break

                elif usr_input2 == 'q':
                    print("Exiting program")
                    return

                else:
                    print("Input not recognized, please try again.")
                    print()

        elif usr_input == 'q':
            print("Exiting program")
            return

        else:
            print("Input not recognized, please try again.")
            print()

if __name__ == '__main__':
    main()
