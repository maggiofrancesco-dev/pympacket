import cmd
import argparse
import re
from pympacket.attacks.GetNPUsers import GetUserNoPreAuth
from pympacket.utils.bruteforce import build_krb5asrep_hash, Target

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
        parser.add_argument_group()

        try:
            args = parser.parse_args(args.split())
            if not (args.username and args.password) and not args.wordlist:
                parser.error("Username and password or a wordlist are required.")
            print(f"Domain Controller IP: {args.dc_ip}")
        except SystemExit:
            print("Invalid arguments. Use 'help get_users' for usage details.")
            parser.print_help()

        cmdLineOptions = {"no_pass": True if args.wordlist else False, "usersfile": args.wordlist, "k": False}

        npu = GetUserNoPreAuth(username=args.username, password=args.password, domain=args.domain, cmdLineOptions=cmdLineOptions)

        # test = Target(username='l.douglas', domain='contoso.local', hash='$krb5asrep$23$l.douglas@CONTOSO.LOCAL:9f13fafda4096f35b829f6a9f5045d29$d4bf323934e5b21d21c83bfcdc294fcc26af6d03c372a4a5b45b32d05e3d6e1fe3a90bccbcf8683b14a1c74d50a3c9e1c9ecca2c4aacdb254ed009ebd1770502c66ed54d9a40604639269d60e9c0c12fff1e1c9f03198578dfccd1736d93cf940408a4636402a13e2e1d9d25f50421b6f309bfa7b1b327b3e91ac7fe3414a76437dc12f0d2100dc407a8af2a14e23aae24b12948c7c814489118671f875835eab7934a7cd3199ca00f8f8847780b9f569fe0500ebdf30ce1cee97bb52cf9807df64ea67caf5357eddb38f4bb6c9c4f8245382c3abc890cd5b845faf0d0eab8ee0ab3f1c40994766b8e01b09dc2d5')

        # print(build_krb5asrep_hash(password='Football1', target=test))

        npu.run()

    def do_quit(self, line):
        """Exit the CLI."""
        return True
    pass