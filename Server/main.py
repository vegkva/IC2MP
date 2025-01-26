from icmp_server import *


def check_if_client_offline():
    while True:
        for client in client_manager.get_clients():
            if client.get_client_ready():
                if not client.check_if_alive():
                    client_manager.print_clients()

def clients_dashboard_thread():
    while True:
        try:
            cmd = session.prompt(FormattedText([
                ('class:bright',"\n> " if len(client_manager.get_client_active()) == 0 else f"\n{client_manager.get_client_active()}> ")
                ]), style=style).strip()
            cmd_handler.handle_command(cmd)
        except (EOFError, KeyboardInterrupt):
            # Handle end of file (Ctrl+D) or interrupt (Ctrl+C)
            break



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




    # Create a key bindings object
    kb = KeyBindings()

    # Add the control-z key binding to suspend the application
    @kb.add(Keys.ControlZ)
    def _(event):
        os.kill(os.getpid(), signal.SIGTSTP)

    session = PromptSession(key_bindings=kb, enable_suspend=True, completer=ContextSensitiveCompleter(cmd_handler.get_commands(), client_manager.get_use_options()))
    

    # Create and start the clients_dashboard thread
    t1 = threading.Thread(target=clients_dashboard_thread, name='t1')
    t1.start()

    # Create and start a thread for sniffing
    t2 = threading.Thread(target=sniff, kwargs={'filter': 'icmp', 'prn': reply_to_client})
    t2.start()

    # Create and start a thread for sniffing
    t3 = threading.Thread(target=check_if_client_offline(), name='t3')
    t3.start()

    # Optionally, join threads if you want to wait for them to finish
    t1.join()
    t2.join()
    t3.join()

