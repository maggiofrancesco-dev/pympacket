import ldap3
import struct
from dns import resolver
import sys
from pprint import pprint

def ldap_login(target, user, password, domain):
    domain_base = get_domain_base(domain)
    try:
        server = ldap3.Server(host=target, port=389, use_ssl=False)
    except:
        print("Host unreachable, the target provided must be the DC.", file=sys.stderr)
        return None
    try:
        conn = ldap3.Connection(server, user=f"{domain}\\{user}", password=password, auto_bind=True, authentication=ldap3.NTLM)
    except:
        print("Invalid credentials provided.", file=sys.stderr)
        return None
    return conn, domain_base

def get_domain_base(domain):
    domain_base = ''
    split_domain = domain.split('.')
    for dom_slice in split_domain:
        domain_base = domain_base + f'dc={dom_slice},'

    domain_base = domain_base[:-1]
    return domain_base

def sidFromBytes(byte_sid):
    revision = byte_sid[0]
    sub_auth_count = byte_sid[1]
    identifier_authority = int.from_bytes(byte_sid[2:8], 'big')
    sub_authorities = struct.unpack("<{}L".format(sub_auth_count), byte_sid[8:])
    sid_string = "S-{}-{}".format(revision, identifier_authority)
    for sub_authority in sub_authorities:
        sid_string += "-{}".format(sub_authority)

    return sid_string

def domain_sid(conn, domain_base):
    conn.search(search_base=domain_base, search_filter="(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=8192))", attributes=["objectSid"])
    for entry in conn.entries:
        byte_sid = entry['objectSid'].raw_values
        sid = sidFromBytes(byte_sid[0])
        sid = sid[:sid.rfind('-')]
        return sid

def group_member(conn, domain_base, group):
    group_members_dn = []
    group_members = []
    conn.search(search_base=domain_base, search_filter=f"(&(objectCategory=group)(|(samAccountName={group})))", attributes=["member"])
    for entry in conn.entries:
        members = entry['member'].raw_values
        if len(members):
            for member in members:
                group_members_dn.append(member.decode("utf-8"))
    for member_dn in group_members_dn:
        conn.search(search_base=domain_base, search_filter=f"(distinguishedName={member_dn})", attributes=["sAMAccountName"])
        for entry in conn.entries:
            group_members.append((entry['sAMAccountName'].raw_values)[0].decode("utf-8"))
    return group_members

def get_user_groups(conn, domain_base, memberOf):
    user_groups = []
    groups_dn = memberOf
    if len(groups_dn):
        for group_dn in groups_dn:
            conn.search(search_base=domain_base, search_filter=f"(distinguishedName={group_dn.decode('utf-8')})", attributes=["sAMAccountName"])
            for entry in conn.entries:
                user_groups.append((entry['sAMAccountName'].raw_values)[0].decode("utf-8"))
    return user_groups

def enum_users(conn, domain_base):
    conn.search(search_base=domain_base, search_filter="(&(samAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", attributes=["sAMAccountName", "memberOf", "adminCount", "description", "objectSid"])
    users = []
    for entry in conn.entries:
        user = {}
        user_sid = sidFromBytes(entry['objectSid'].raw_values[0])
        user['rid'] = user_sid[user_sid.rfind('-')+1:]
        user['username'] = (entry['sAMAccountName'].raw_values)[0].decode("utf-8")
        user['adminCount'] = int((entry['adminCount'].raw_values)[0].decode("utf-8")) if len(entry['adminCount'].raw_values) else 0
        user['Description'] = (entry['description'].raw_values)[0].decode("utf-8")  if len(entry['description'].raw_values) else ""
        user_groups = []
        if len(entry['memberOf'].raw_values):
            user_groups = get_user_groups(conn, domain_base, entry['memberOf'].raw_values)
        user['memberOf'] = user_groups
        users.append(user)
    return users

def get_dcs(conn, domain_base):
    dcs = []
    conn.search(search_base=f"OU=Domain Controllers,{domain_base}", search_filter="(samAccountType=805306369)", attributes=["sAMAccountName"])
    for entry in conn.entries:
        dcs.append((entry['sAMAccountName'].raw_values)[0].decode("utf-8"))
    return dcs

def enum_computers(conn, domain_base, dc_ip):
    res = resolver.Resolver()
    res.nameservers = [dc_ip]
    dcs = get_dcs(conn, domain_base)
    conn.search(search_base=domain_base, search_filter="(samAccountType=805306369)", attributes=["sAMAccountName", "dNSHostName"])
    computers = []
    for entry in conn.entries:
        computer = {}
        computer['name'] = (entry['sAMAccountName'].raw_values)[0].decode("utf-8")

        if computer['name'] in dcs:
            computer['is_dc'] = True
        else:
            computer['is_dc'] = False

        if len(entry['dNSHostName'].raw_values):
            computer['dns_hostname'] = (entry['dNSHostName'].raw_values)[0].decode("utf-8")
            answer = res.resolve(computer['dns_hostname'], tcp=True)
            computer['ip_address'] = answer[0].address
        else:
            computer['dns_hostname'] = ""
            computer['ip_address'] = ""
        computers.append(computer)
    return computers


#conn, domain_base = ldap_login(target="87.0.192.165", user="l.douglas", password="Football1", domain="contoso.local")
## Output is a string containing the Domain SID
#print(domain_sid(conn, domain_base))
#
## Output is a list og group members in the following format:
## ['m.summers', 'd.garza', 'Administrator']
#print(group_member(conn, domain_base, "Domain Admins"))
#
## Output is a list of dict in the following format:
## {'Description':'', 'adminCount':1, 'memberOf':['WebAdmins', 'Domain Admins'], 'rid':'1657', 'username':'m.summers'}
#pprint(enum_users(conn, domain_base))
#
## Output is a list of dict in the following format:
## {'dns_hostname':'DC01.contoso.local', 'ip_address':'192.168.56.133', 'is_dc':True, 'name':'DC01$'}
#pprint(enum_computers(conn, domain_base, "87.0.192.165"))