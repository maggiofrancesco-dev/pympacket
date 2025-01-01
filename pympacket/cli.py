import cmd
import argparse
import re
from pympacket.attacks.GetNPUsersbak import GetUserNoPreAuth

def ipv4_address(value):
    # Regular expression to match an IPv4 address (four octets)
    pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if not re.match(pattern, value):
        raise argparse.ArgumentTypeError(f"Invalid IPv4 address: {value}")
    return value

class ImpacketCLI(cmd.Cmd):
    # Your CLI commands and functionality will go here
    prompt = '>> '
    intro = 'Welcome to Pympacket. Type "help" for available commands.'  # Your intro message
    found_hashes: list[str] = []
    found_users: list[str] = []
    
    def do_enum(self, args):
        """Get hashes of users with no pre-authentication"""
        parser = argparse.ArgumentParser(prog='enum', description='Runs an enumeration test.')
        parser.add_argument('-d', '--domain', type=str, required=True, help='The domain to test.')
        parser.add_argument('-dcip', '--dc-ip', type=ipv4_address, required=True, help='The ip of the domain controller. (IPv4)')

        group = parser.add_argument_group()

        group.add_argument('-u', '--username', type=str, required=False, help='The username to test.')
        group.add_argument('-p', '--password', type=str, required=False, help='The password to test.')
        group.add_argument('-w', '--wordlist', type=str, required=False, help='The wordlist containing the users to test.')
        group.add_argument('-v', '--verbose', type=bool, required=False, help='Whether to print the process or not.')

        try:
            args = parser.parse_args(args.split())
            if not (args.username and args.password) and not args.wordlist:
                parser.error("Username and password or a wordlist are required.")
        except SystemExit:
            print("Invalid arguments. Use 'help get_users' for usage details.")
            parser.print_help()

        cmdLineOptions = {"no_pass": True if args.wordlist else False, "usersfile": args.wordlist, "k": False, 'verbose': args.verbose}

        npu = GetUserNoPreAuth(username=args.username, password=args.password, domain=args.domain, cmdLineOptions=cmdLineOptions)

        hashes = npu.run()

        for hash in hashes:
            # Split the hash by `$` to isolate the user@domain part
            user_realm = hash.split('$')[3]

            # Split the user@domain part by `@` to get only the user
            user = user_realm.split('@')[0]
            if user not in self.found_users:
                self.found_users.append(user)
                self.found_hashes.append(hash)
            else:
                self.found_hashes[self.found_users.index(user)] = hash

        print(f'Found {len(hashes)} vulnerable hashes.')

    def do_list(self, args):
        """List found vulnerable hases."""
        for hash in self.found_hashes:
            print(f'{hash}\n')
        if len(self.found_hashes) == 0:
            print('No hashes stored in memory.')

    def do_quit(self, line):
        """Exit the CLI."""
        return True
    pass