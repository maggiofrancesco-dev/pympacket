import ldap3
import struct
from dns import resolver
import sys

class ldap_enum():
    """Class to perform common types of enumeration against the LDAP server hosted on Domain Controllers"""

    def __init__(self):
        pass

    def login(self, target, domain, user=None, password=None, pth=False):
        """Perform Anonymous/NTLM authentication against a LDAP Server for further querying"""
        # If Pass-The-Hash is used, prepend an empty LM hash before the actual NT hash
        if pth:
            password = f"aad3b435b51404eeaad3b435b51404ee:{password}"

        # Convert domain name to an LDAP Domain Base
        domain_base = self.get_domain_base(domain)

        try:
            server = ldap3.Server(host=target, port=389, use_ssl=False)
        except:
            print("Host unreachable, the target provided must be the DC.\n", file=sys.stderr)
            return None, None
        if user == None or password == None: # Anonymous Bind
            try:
                conn = ldap3.Connection(server, auto_bind=True, authentication=ldap3.ANONYMOUS)
            except:
                print("Error during anonymous bind.\n", file=sys.stderr)
                return None, None
            if self.domain_sid(conn, domain_base) == None: # Check if you can actually retrieve informations on an anonymous bind
                print("Anonymous login not available of this server.\n", file=sys.stderr)
                return None, None
        else: # NTLM Auth
            try:
                conn = ldap3.Connection(server, user=f"{domain}\\{user}", password=password, auto_bind=True, authentication=ldap3.NTLM)
            except:
                print("Invalid credentials provided.\n", file=sys.stderr)
                return None, None
        return conn, domain_base

    def get_domain_base(self, domain):
        """Convert domain name in a LDAP domain base"""
        domain_base = ''
        split_domain = domain.split('.')
        for dom_slice in split_domain:
            domain_base = domain_base + f'dc={dom_slice},'

        domain_base = domain_base[:-1]
        return domain_base

    def sidFromBytes(self, byte_sid):
        """Converts the raw SID obtained from a LDAP query to a readable format"""
        revision = byte_sid[0]
        sub_auth_count = byte_sid[1]
        identifier_authority = int.from_bytes(byte_sid[2:8], 'big')
        sub_authorities = struct.unpack("<{}L".format(sub_auth_count), byte_sid[8:])
        sid_string = "S-{}-{}".format(revision, identifier_authority)
        for sub_authority in sub_authorities:
            sid_string += "-{}".format(sub_authority)

        return sid_string

    def domain_sid(self, conn, domain_base):
        """Retrieve the Domain SID"""
        conn.search(search_base=domain_base, search_filter="(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=8192))", attributes=["objectSid"])
        for entry in conn.entries:
            byte_sid = entry['objectSid'].raw_values
            sid = self.sidFromBytes(byte_sid[0]) # Convert raw SID to a readable format
            sid = sid[:sid.rfind('-')]
            return sid

    def group_member(self, conn, domain_base, group):
        """Retrieve members of a specific group"""
        group_members_dn = []
        group_members = []
        # Retrieve group member's distinguished names
        conn.search(search_base=domain_base, search_filter=f"(&(objectCategory=group)(|(samAccountName={group})))", attributes=["member"])
        for entry in conn.entries:
            members = entry['member'].raw_values
            if len(members):
                for member in members:
                    group_members_dn.append(member.decode("utf-8"))
        for member_dn in group_members_dn:
            # Get members samaccountname from their distinguishedName
            conn.search(search_base=domain_base, search_filter=f"(distinguishedName={member_dn})", attributes=["sAMAccountName"])
            for entry in conn.entries:
                group_members.append((entry['sAMAccountName'].raw_values)[0].decode("utf-8"))
        return group_members

    def get_user_groups(self, conn, domain_base, memberOf):
        """Retrieve the samaccountname of the provided list of groups in distinguishedName format"""
        user_groups = []
        groups_dn = memberOf
        if len(groups_dn):
            for group_dn in groups_dn:
                # Retrieve the 'samaccountname' of the group from its 'distinguishedName'
                conn.search(search_base=domain_base, search_filter=f"(distinguishedName={group_dn.decode('utf-8')})", attributes=["sAMAccountName"])
                for entry in conn.entries:
                    user_groups.append((entry['sAMAccountName'].raw_values)[0].decode("utf-8"))
        return user_groups

    def enum_users(self, conn, domain_base):
        """Retrieve Domain Users information and their groups membership"""
        # Search for active Domain Users and retrieve useful attributes for each of them
        conn.search(search_base=domain_base, search_filter="(&(samAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", attributes=["sAMAccountName", "memberOf", "adminCount", "description", "objectSid"])
        users = []
        for entry in conn.entries:
            user = {}
            # Convert user SID to readable format
            user_sid = self.sidFromBytes(entry['objectSid'].raw_values[0])
            user['rid'] = user_sid[user_sid.rfind('-')+1:]
            user['username'] = (entry['sAMAccountName'].raw_values)[0].decode("utf-8")
            user['adminCount'] = int((entry['adminCount'].raw_values)[0].decode("utf-8")) if len(entry['adminCount'].raw_values) else 0
            user['description'] = (entry['description'].raw_values)[0].decode("utf-8")  if len(entry['description'].raw_values) else ""
            user_groups = []
            if len(entry['memberOf'].raw_values):
                # Retrieve 'samaccountname' of the user groups from the 'distinguished name' format
                user_groups = self.get_user_groups(conn, domain_base, entry['memberOf'].raw_values)
            user['memberOf'] = user_groups
            users.append(user)
        return users

    def get_dcs(self, conn, domain_base):
        """Retrieve Domain Controllers"""
        dcs = []
        # Search for computer objects under the 'Domain Controllers' root OU, to retrieve domain controllers
        conn.search(search_base=f"OU=Domain Controllers,{domain_base}", search_filter="(samAccountType=805306369)", attributes=["sAMAccountName"])
        for entry in conn.entries:
            dcs.append((entry['sAMAccountName'].raw_values)[0].decode("utf-8"))
        return dcs

    def enum_computers(self, conn, domain_base, dc_ip):
        """Retrieve Domain Computers and their ip addresses when possible"""
        # Setup dns resolver using DC ip address
        res = resolver.Resolver()
        res.nameservers = [dc_ip]

        # Retrieve domain controllers
        dcs = self.get_dcs(conn, domain_base)

        # Search for computer objects
        conn.search(search_base=domain_base, search_filter="(samAccountType=805306369)", attributes=["sAMAccountName", "dNSHostName"])
        computers = []
        for entry in conn.entries:
            computer = {}
            computer['name'] = (entry['sAMAccountName'].raw_values)[0].decode("utf-8")

            # Check if the computer is a DC
            if computer['name'] in dcs:
                computer['is_dc'] = True
            else:
                computer['is_dc'] = False

            # Try to resolve the dns hostname of the computer using the DC as dns server to retrieve the computer's ip address
            if len(entry['dNSHostName'].raw_values):
                computer['dns_hostname'] = (entry['dNSHostName'].raw_values)[0].decode("utf-8")
                answer = res.resolve(computer['dns_hostname'], tcp=True)
                computer['ip_address'] = answer[0].address
            else:
                computer['dns_hostname'] = ""
                computer['ip_address'] = ""
            computers.append(computer)
        return computers