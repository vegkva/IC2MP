from helpers import *


class ClientManager:
    def __init__(self):
        self.clients = []  # Still keeping list for ordering
        self.client_map = {}  # {client_id: client} for quick lookups
        self.use_options = []  # Using set for uniqueness
        self.client_active = ""

    def add_client(self, new_client):
        client_id = new_client.get_id()
        if client_id in self.client_map:
            print("add_client() already connected")
            existing_client = self.client_map[client_id]
            existing_client.activate()  # Ensure the client is activated
            return f"Client: {client_id} already connected"

        self.clients.append(new_client)
        self.client_map[client_id] = new_client
        self.use_options.append(client_id)

    def remove_client(self, client_to_remove):
        client_id = client_to_remove.get_id()
        if self.client_active == client_id:
            self.client_active = ""

        if client_id in self.client_map:
            self.clients.remove(client_to_remove)
            del self.client_map[client_id]
            self.use_options.remove(client_id)

    def print_client(self, client_to_print):
        if client_to_print in self.client_map.values():
            client_to_print.print_attributes()

    def set_client_active(self, active_client):
        self.client_active = active_client.get_id()

    def clear_client_active(self):
        self.client_active = ""

    def get_client_active(self):
        return self.client_active

    def get_clients(self):
        return self.clients

    def get_client(self, id_value):
        return self.client_map.get(id_value)  # O(1) lookup

    def get_use_options(self):
        return self.use_options  # Convert to list if needed

    def cmd_all_clients(self, cmd):
        for client in self.clients:
            client.set_server_command(cmd)

    def print_clients(self):
        if self.clients:
            print_formatted_text(FormattedText([
                ('class:ul_bold', f"\nClient ID\t\tUser\t\t\t\t\tTimeout\t\t\tCommand\t\t\t\t\tOutput file")
            ]), style=style)

            for client in self.clients:
                client.print_info(self.client_active)
        else:
            print("No clients connected :/")
