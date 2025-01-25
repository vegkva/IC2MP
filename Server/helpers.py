

def decode_hex_to_bytes(hex_cipher_tag):
    ciphertext_ascii = ""
    for c in hex_cipher_tag:
        ciphertext_ascii += chr((int(c, 16)))
    #print(ciphertext_ascii)    
    ciphertext_ascii_bytes = ciphertext_ascii.encode().decode('unicode_escape').encode("raw_unicode_escape")

    return ciphertext_ascii_bytes#, tag_ascii_bytes, nonce_ascii_bytes


def string_to_list(string):
    #no_padding = remove_padded_zeroes(string)
    #print(no_padding)
    n = 2
    cipher_block = [('0x'+string[i:i+n]) for i in range(0, len(string), n)]
    return cipher_block

def remove_padded_zeroes(string):
    if string == len(string) * string[0]:
        return ""
    zeroes_present = False
    for i in range(2, len(string),2):
        check = string[len(string)-i:]
        if "0" in check and check == len(check) * check[0]:
            zeroes_present = True
            continue
        else:
            check = check[2:]
            break
    if not zeroes_present:
        return string
    else:
        return string[:-(len(check))]
