class ClientManager:
    def __init__(self):
        self.clients = []
        self.use_options = []
        self.client_active = ""

    def add_client(self, new_client):
        unique = False
        for client in self.clients:
            if client.get_id() == new_client.get_id():
                client.activate()
                return f"Client: {new_client.get_id()} already connected" # Should activate (client.activate()) the client in order for time_manager to be updated
        self.clients.append(new_client)
        self.use_options.append(new_client.get_id())


    def remove_client(self, client_to_remove):
        if self.client_active == client_to_remove.get_id():
            self.client_active = ""
        self.clients.remove(client_to_remove)
        self.use_options.remove(client_to_remove.get_id())


    def print_client(self, client_to_print):
        for client in self.clients:
            if client == client_to_print:
                #print(client)
                client.print_attributes()

    def set_client_active(self, active_client):
        self.client_active = active_client.get_id()

    def clear_client_active(self):
        self.client_active = ""

    def get_client_active(self):
        return self.client_active

    def get_clients(self):
        return self.clients

    def get_client(self, id_value):
        for client in self.clients:
            if client.get_id() == id_value:
                return client

    def get_use_options(self):
        return self.use_options

    def cmd_all_clients(self, cmd):
        for client in self.clients:
            client.set_server_command(cmd)