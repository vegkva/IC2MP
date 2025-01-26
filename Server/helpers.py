from prompt_toolkit import print_formatted_text, HTML
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.keys import Keys
from prompt_toolkit import PromptSession
from crypto import *
import os
import datetime
from prompt_toolkit.styles import Style

style = Style.from_dict({
        'red': 'ansired',
        'green': 'ansigreen',
        'bold_blue': 'ansiblue bold',
        'bright_yellow': 'ansiyellow',
        'bg_magenta': 'bg:ansimagenta',
        'bg_rgb': 'bg:#222222',
        'fg_rgb': '#ff00ff',
        'bright': 'ansiwhite bold',
        'ul_bold':'underline bold'
    })


def write_result_to_file(client):
    if not os.path.exists(client.get_id()):
        os.makedirs(client.get_id())
    date_time = datetime.datetime.now().strftime("%D - %H:%M:%S ")
    if client.get_client_response():
        if (client.get_client_response() != "¤ping" and client.get_server_command()) or (not client.get_server_command()):
            with open(client.get_id()+"/output.txt", 'a') as f:
                f.write(date_time + "\n" + f"User: {client.get_whoami()}\n" + f"Server command: {client.get_server_command()}\n" + client.get_client_response()+"\n\n")


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
