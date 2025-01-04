import cmd
import argparse
import re
from pympacket.utils.bruteforce import bruteforce
from pympacket.attacks.GetNPUsersbak import GetUserNoPreAuth
from pympacket.utils.storage import load_storage, save_storage, Storage
from pympacket.utils.kerberoasting import kerberoast
from pympacket.models.common import Hash, CrackedUser
from typing import Any
import os

def ipv4_address(value):
    # Regular expression to match an IPv4 address (four octets)
    pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if not re.match(pattern, value):
        raise argparse.ArgumentTypeError(f"Invalid IPv4 address: {value}")
    return value

def extract_user(hash: Hash):
    # Split the hash by `$` to isolate the user@domain part
    user_realm = hash.value.split('$')[3]

    # Split the user@domain part by `@` to get only the user
    return user_realm.split('@')[0]

class ImpacketCLI(cmd.Cmd):
    # Your CLI commands and functionality will go here
    prompt = '>> '
    intro = 'Welcome to Pympacket. Type "help" for available commands.'  # Your intro message
    storage: Storage

    def __init__(self):
        super().__init__()
        self.storage = load_storage()

    def save_hash(self, hash: Hash):
        user = extract_user(hash)
        if user not in self.storage.found_users:
            self.storage.found_users.append(user)
            self.storage.found_hashes.append(hash)
        else:
            self.storage.found_hashes[self.storage.found_users.index(user)] = hash
        save_storage(self.storage)

    def save_password(self, password: str, hash: Hash):
        self.storage.cracked_hashes.append(CrackedUser(username=extract_user(hash), password=password, hash=hash))
        save_storage(self.storage)

    
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
        group.add_argument('-t', '--type', type=str, choices=['auto', 'asrep', 'spn', 'ldap'] , required=False, default='auto', help='What kind of enumeration to perform.')

        try:
            args = parser.parse_args(args.split())
            if not (args.username and args.password) and not args.wordlist:
                parser.error("Username and password or a wordlist are required.")
            if args.type == 'spn' and not (args.username and args.password):
                parser.error("Username and password are required to perform SPNs enumeration.")
            if args.type == 'ldap' and not (args.username and args.password):
                parser.error("Username and password are required to perform LDAP enumeration.")


            cmdLineOptions = {"no_pass": True if args.wordlist else False, "usersfile": args.wordlist, "k": False, 'verbose': args.verbose, "dc_host": None, "dc_ip": args.dc_ip}

            npu = GetUserNoPreAuth(username=args.username, password=args.password, domain=args.domain, cmdLineOptions=cmdLineOptions)

            # TODO: Add enumeration for spns users and ldap when with credentials

            hashes = npu.run()

            for hash in hashes:
                self.save_hash(Hash(value=hash, type='asrep'))

            if args.type == 'spn' or (args.type == 'auto' and args.username and args.password):
                users = kerberoast(username=args.username, domain=args.domain, dc_ip=args.dc_ip, password=args.password)
                for user in users:
                    self.save_hash(user.hash)

            print(f'Found {len(hashes)} vulnerable hashes.')

        except SystemExit:
            print("Invalid arguments. Use 'help enum' for usage details.")

    def do_bruteforce(self, args):
        """Offline bruteforce found  hashes."""
        parser = argparse.ArgumentParser(prog='bruteforce', description='Performs an offline bruteforce.')

        parser.add_argument('-w', '--wordlist', type=str, required=True, help='The wordlist containing the users to test.')
        parser.add_argument('-t', '--type', type=str, choices=['auto', 'asrep', 'tgs'], required=False, default='auto', help='The wordlist containing the users to test.')
        parser.add_argument('-v', '--verbose', type=bool, required=False, help='Whether to print the process or not.')

        try:
            args = parser.parse_args(args.split())
        except SystemExit:
            print("Invalid arguments. Use 'help bruteforce' for usage details.")

        found_passwords = 0
        
        for hash in self.storage.found_hashes:
            if (args.type == hash.type or args.type == 'auto'):
                password = bruteforce(args.wordlist, hash)
                if password:
                    found_passwords+=1
                    self.save_password(password, hash)

        print(f'Cracked {found_passwords} vulnerable hashes.')

    def do_list_hashes(self, args):
        """List found vulnerable hashes."""
        for hash in self.storage.found_hashes:
            print(f'{hash}\n')
        if len(self.storage.found_hashes) == 0:
            print('No hashes stored in memory.')
    
    def do_list_users(self, args):
        """List cracked users credentials."""
        for user in self.storage.cracked_hashes:
            print(f'{user}\n')
        if len(self.storage.cracked_hashes) == 0:
            print('No users stored in memory.')

    def do_clear(self, args):
        """Clear the CLI."""
        # For Windows
        if os.name == 'nt':
            os.system('cls')
        # For Linux and macOS
        else:
            os.system('clear')

    def do_forget(self, args):
        """Clears the saved storage and memory."""
        self.storage = Storage()
        save_storage(self.storage)

    def do_quit(self, line):
        """Exit the CLI."""
        save_storage(self.storage)
        return True
    pass