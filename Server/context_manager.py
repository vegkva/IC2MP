from prompt_toolkit.completion import Completer, Completion

class ContextSensitiveCompleter(Completer):
    def __init__(self, commands, use_options):
        self.commands = commands
        self.use_options = use_options

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        
        # Provide completions based on the command
        if text.startswith('use '):
            # If the command is 'use', provide use_options completions
            for option in self.use_options:
                if option.startswith(text[len(text)+1:]):  # Check after 'use '
                    yield Completion(option, start_position=-len(text)+4)
        else:
            # Provide general command completions
            for command in self.commands:
                if command.startswith(text):
                    yield Completion(command, start_position=-len(text))