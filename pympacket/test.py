from pympacket.utils.asreproasting import asreproast
from pympacket.utils.kerberoasting import kerberoast
from pympacket.utils.raw_ldap_enum import ldap_enum
from pympacket.utils.check_admin_smb import check_admin_smb
from pympacket.utils.storage import Storage, load_storage, save_storage
import argparse
from pprint import pprint
import cmd
import os
from pympacket.models.common import Domain, User, Hash, Computer
import re

def ipv4_address(value):
    # Regular expression to match an IPv4 address (four octets)
    pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if not re.match(pattern, value):
        raise argparse.ArgumentTypeError(f"Invalid IPv4 address: {value}")
    return value

def ldap_enum_output(ldap, conn, domain_base, domain, dc_ip):
    domain_info = Domain()
    domain_info.name = domain
    # Enumerate Domain SID
    domain_sid = ldap.domain_sid(conn, domain_base)
    print(f"Domain SID ({domain}): {domain_sid}\n")
    domain_info.sid = domain_sid

    # Enumerate Domain Admins
    domain_admins = ldap.group_member(conn, domain_base, "Domain Admins")
    print("Members of 'Domain Admins':")
    for da in domain_admins:
        print(da)
    print("")

    domain_info.domain_admins = domain_admins

    # Enumerate Domain Users
    domain_users = ldap.enum_users(conn, domain_base)
    print("Domain User Accounts:")
    for user in domain_users:
        print("------------------------------------------")
        print(f"RID: {user['rid']}")
        print(f"Username: {user['username']}")
        print(f"Description: {user['description']}")
        if len(user['memberOf']):
            groups = ""
            for group in user['memberOf']:
                groups += f"{group}, "
            groups = groups[:-2]
        print(f"Groups: {groups}")
        print(f"AdminCount: {user['adminCount']}")
    print("------------------------------------------\n")

    # Enumerate Domain Computers
    computer_objects = []
    domain_computers = ldap.enum_computers(conn, domain_base, dc_ip)
    print("Domain Computers:")
    for computer in domain_computers:
        current_computer = Computer()
        current_computer.name = computer['name']
        current_computer.dns_name = computer['dns_hostname']
        current_computer.ip_address = computer['ip_address']
        current_computer.dc = computer['is_dc']
        if computer['is_dc']:
            domain_info.dc.append(dc_ip)
        computer_objects.append(current_computer)
        print("------------------------------------------")
        print(f"Computer Name: {computer['name']}")
        print(f"DNS Hostname: {computer['dns_hostname']}")
        print(f"IP Address: {computer['ip_address']}")
        print(f"Domain Controller: {computer['is_dc']}")
    print("------------------------------------------\n")
    domain_info.domain_computers = computer_objects
    return domain_info

class ImpacketCLI(cmd.Cmd):
    prompt = '>> '
    intro = 'Welcome to Pympacket. Type "help" for available commands.'
    storage: Storage

    def __init__(self):
        super().__init__()
        self.storage = load_storage()

    def do_enum(self, args):
        """ Perform Domain Enumeration """
        parser = argparse.ArgumentParser(prog='enum', description='Runs an enumeration test.')
        parser.add_argument('-d', '--domain', type=str, required=True, help='The domain to test.')
        parser.add_argument('-dc-ip', type=ipv4_address, required=True, help='The ip of the domain controller. (IPv4)')
        group = parser.add_argument_group()
        group.add_argument('-u', '--username', type=str, required=False, help='The username to test.')
        group.add_argument('-p', '--password', type=str, required=False, help='The password to test.')
        group.add_argument('-nthash', type=str, required=False, help='The NT hash of the user.')
        group.add_argument('-w', '--wordlist', type=str, required=False, help='The wordlist containing the users to test.')
        group.add_argument('-t', '--type', type=str, choices=['auto', 'asrep', 'kerberoast', 'ldap', 'admin'] , required=False, default='auto', help='What kind of enumeration to perform.')
        args = parser.parse_args(args.split())

        if (args.username and (args.password or args.nthash)):
            # Credentialed        
            if args.type == 'auto' or args.type == 'ldap':
                ldap = ldap_enum()
                if args.nthash == None: # Password login
                    conn, domain_base = ldap.login(target=args.dc_ip, user=args.username, password=args.password, domain=args.domain, pth=False)
                else:
                    conn, domain_base = ldap.login(target=args.dc_ip, user=args.username, password=args.nthash, domain=args.domain, pth=True)
                
                # LDAP Enumeration Output
                asd = ldap_enum_output(ldap, conn, domain_base, args.domain, args.dc_ip)
                print(asd)

                # Enumerate Administrative Privilege
            if args.type == 'auto' or args.type == 'admin':
                ldap = ldap_enum()
                if args.nthash == None: # Password login
                    conn, domain_base = ldap.login(target=args.dc_ip, user=args.username, password=args.password, domain=args.domain, pth=False)
                else:
                    conn, domain_base = ldap.login(target=args.dc_ip, user=args.username, password=args.nthash, domain=args.domain, pth=True)
                    
                domain_computers = ldap.enum_computers(conn, domain_base, args.dc_ip)
                print("Checking if the current user is a Local Administrator on a Domain Computer:")
                admin_on = []
                for computer in domain_computers:
                    if computer['ip_address']:
                        if args.nthash == None:
                            result = check_admin_smb(target=computer['ip_address'], username=args.username, domain=args.domain, password=args.password)
                        else:
                            result = check_admin_smb(target=computer['ip_address'], username=args.username, domain=args.domain, nthash=args.nthash)
                        if result:
                            admin_on.append(computer['name'])
                    
                if len(admin_on):
                    for pc in admin_on:
                        print(pc)
                else:
                    print("The current user does not have Local Administrator privileges on any Domain Computer.")
            print("")

            if args.type == 'auto' or args.type == 'asrep':
                asrep_out = asreproast(dc_ip=args.dc_ip, username=args.username, password=args.password, domain=args.domain)
                pprint(asrep_out)

            if args.type == 'auto' or args.type == 'kerberoast':
                tgs_out = kerberoast(username=args.username, password=args.password, nthash=args.nthash, dc_ip=args.dc_ip, domain=args.domain)
                pprint(tgs_out)

        elif (args.wordlist):
            # Uncredentialed
            if args.type == 'auto' or args.type == 'asrep':
                asrep_out = asreproast(dc_ip=args.dc_ip, domain=args.domain, usersfile=args.wordlist)
                pprint(asrep_out)

            if args.type == 'auto' or args.type == 'ldap':
                ldap = ldap_enum()
                conn, domain_base = ldap.login(target=args.dc_ip, domain=args.domain)
                if conn == None:
                    return None
                ldap_enum_output(ldap, conn, domain_base, args.domain, args.dc_ip)
                
            if args.type == 'kerberoast' or args.type == 'admin':
                print("You can't perform kerberoasting or check for Local Admin privileges without a valid set of user credentials.")
                return None
        else:
            print("You must specify an user wordlist to perform uncredentialed enumeration")
            return None

    def do_list_users(self, args):
        """List cracked users credentials."""
        for user in self.storage.users:
            print(f'{user}\n')
        if len(self.storage.users) == 0:
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



cmdLineOptions = argparse.Namespace(
    #username='m.summers',
    #password='&e}h.aj)9?g*',
    #username='l.douglas',
    #password='Football1',
    username=None,
    password=None,
    domain='contoso.local',
    dc_ip='192.168.116.10',
    wordlist='/home/sumzero/pympacket/SamAccountNames.txt',
    type='auto', # 'auto', 'asrep', 'kerberoast', 'ldap', 'admin'
    nthash=None
)

def main():
    cli = ImpacketCLI()
    cli.cmdloop()

# Entry point of the script
if __name__ == "__main__":
    main()

#enumeration(cmdLineOptions)