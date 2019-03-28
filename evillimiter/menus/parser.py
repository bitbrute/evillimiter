import enum
import collections

from evillimiter.console.io import IO


class CommandParser(object):
    class CommandType(enum.Enum):
        PARAMETER_COMMAND = 1
        FLAG_COMMAND = 2
        PARAMETERIZED_FLAG_COMMAND = 3

    FlagCommand = collections.namedtuple('FlagCommand', 'type, identifier, name')
    ParameterCommand = collections.namedtuple('ParameterCommand', 'type name')
    Subparser = collections.namedtuple('Subparser', 'identifier subparser handler')

    def __init__(self):
        self._flag_commands = []
        self._parameter_commands = []
        self._subparsers = []

    def add_parameter(self, name):
        """
        Adds a parameter command that does not require an identifier.
        It is required to cover all parameter commands.

        E.g. '24' or 'hello'
        Both are standalone values (parameters).
        """
        command = CommandParser.ParameterCommand(
            type=CommandParser.CommandType.PARAMETER_COMMAND,
            name=name
        )

        self._parameter_commands.append(command)

    def add_flag(self, identifier, name):
        """
        Adds a flag command that does not carry any value.
        Flags are optional.
        E.g. '-verbose'
        """
        command = CommandParser.FlagCommand(
            type=CommandParser.CommandType.FLAG_COMMAND,
            identifier=identifier,
            name=name
        )

        self._flag_commands.append(command)

    def add_parameterized_flag(self, identifier, name):
        """
        Adds a parameterized flag that carries a value.
        Parameterized flags are optional.
        E.g. '-ip 192.168.0.0.1'
        """
        command = CommandParser.FlagCommand(
            type=CommandParser.CommandType.PARAMETERIZED_FLAG_COMMAND,
            identifier=identifier,
            name=name
        )

        self._flag_commands.append(command)

    def add_subparser(self, identifier, handler=None):
        """
        Creates a subparser and adds a command to this parser, making it its parent.
        A subparser is a standalone parser that can contain commands itself.

        E.g. 'git clone'
        In this case 'git' is the parent and 'clone' the subparser
        """
        subparser = CommandParser()
        command = CommandParser.Subparser(
            identifier=identifier,
            subparser=subparser,
            handler=handler
        )

        self._subparsers.append(command)
        return subparser

    def parse(self, command):
        """
        Parses a given list of arguments
        """
        names = [x.name for x in (self._flag_commands + self._parameter_commands)]
        result_dict = dict.fromkeys(names, None)

        # indicates whether or not to skip the next command argument
        skip_next = False

        for i, arg in enumerate(command):
            if skip_next:
                skip_next = False
                continue

            if i == 0:
                # check if the first argument is a subparser
                for sp in self._subparsers:
                    if sp.identifier == arg:
                        # if subparser present, parse arguments there
                        result = sp.subparser.parse(command[(i + 1):])
                        if result is not None and sp.handler is not None:
                            # call the subparser's handler if available
                            sp.handler(result)

                        return result
            
            # indicates whether or not the argument has been processed
            is_arg_processed = False

            for cmd in self._flag_commands:
                if cmd.identifier == arg:
                    if cmd.type == CommandParser.CommandType.FLAG_COMMAND:
                        # if its a flag, set the flag to true
                        result_dict[cmd.name] = True
                        is_arg_processed = True
                        break
                    elif cmd.type == CommandParser.CommandType.PARAMETERIZED_FLAG_COMMAND:
                        if (len(command) - 1) < (i + 1):
                            # no more command arguments to process
                            IO.error('parameter for flag {}{}{} is missing'.format(IO.Fore.LIGHTYELLOW_EX, cmd.name, IO.Style.RESET_ALL))
                            return

                        # if parameterized flag, set value to next argument
                        value = command[i + 1]
                        result_dict[cmd.name] = value

                        # skip the next argument (already processed)
                        skip_next = True

                        is_arg_processed = True
                        break
            
            if not is_arg_processed:
                for cmd in self._parameter_commands:
                    # parameter command, since a flag could not be found
                    if result_dict[cmd.name] is None:
                        # set parameter value
                        result_dict[cmd.name] = arg
                        is_arg_processed = True
                        break

            if not is_arg_processed:
                IO.error('{}{}{} is an unknown command.'.format(IO.Fore.LIGHTYELLOW_EX, arg, IO.Style.RESET_ALL))
                return

        # check if there are any parameters missing
        for cmd in self._parameter_commands:
            if result_dict[cmd.name] is None:
                IO.error('parameter {}{}{} is missing'.format(IO.Fore.LIGHTYELLOW_EX, cmd.name, IO.Style.RESET_ALL))
                return

        # set unspecified flags to False instead of None
        for cmd in self._flag_commands:
            if cmd.type == CommandParser.CommandType.FLAG_COMMAND:
                if result_dict[cmd.name] is None:
                    result_dict[cmd.name] = False

        result_tuple = collections.namedtuple('ParseResult', sorted(result_dict))
        return result_tuple(**result_dict)