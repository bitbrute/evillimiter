import enum
import shlex
import collections

from .parser import CommandParser
from evillimiter.console.io import IO


class CommandCompleter(object):
    def __init__(self, commands, subcommands=None):
        self.commands = commands
        self.subcommands = subcommands or {}

    def complete(self, text, state):
        try:
            import readline
            buffer = readline.get_line_buffer().lstrip()
        except Exception:
            buffer = text

        tokens = buffer.split()

        if not tokens or (len(tokens) == 1 and not buffer.endswith(' ')):
            options = [c for c in self.commands if c.startswith(text)]
        else:
            cmd = tokens[0]
            sub_options = self.subcommands.get(cmd, [])
            options = [s for s in sub_options if s.startswith(text)]

        if state < len(options):
            return options[state]
        return None


class CommandMenu(object):
    def __init__(self):
        self.prompt = '>>> '
        self.parser = CommandParser()
        self._active = False

    def setup_completer(self, commands, subcommands=None):
        try:
            import readline
            completer = CommandCompleter(commands, subcommands)
            readline.set_completer(completer.complete)
        except Exception:
            pass

    def argument_handler(self, args):
        """
        Handles command-line arguments.
        """
        pass

    def interrupt_handler(self):
        """
        Handles a keyboard interrupt in the input loop.
        """
        self.stop()

    def start(self):
        """
        Starts the menu input loop.
        Commands will be processed and handled.
        """
        self._active = True

        while self._active:
            try:
                command = IO.input(self.prompt)
            except KeyboardInterrupt:
                self.interrupt_handler()
                break

            if not command.strip():
                continue

            try:
                tokens = shlex.split(command)
            except ValueError:
                tokens = command.split()

            parsed_args = self.parser.parse(tokens)
            if parsed_args is not None:
                self.argument_handler(parsed_args)

    def stop(self):
        """
        Breaks the menu input loop
        """
        self._active = False
