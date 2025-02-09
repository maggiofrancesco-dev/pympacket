from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import scmr
from impacket.dcerpc.v5.transport import SMBTransport
import sys

def check_admin_smb(target, username, domain, password='', nthash=''):
    """Check if a Domain User has local administrative privileges on a specified computer via SCRM access request"""
    
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

    try:
        # Start DCE/RPC Transport session via the established smb session on port 445, targeting the "\svcctl" named pipe
        # The "\svcctl" named pipe is used to communicate with the Service Control Manager Remote (SCRM) Protocol
        rpctransport = SMBTransport(target, 445, r"\svcctl", smb_connection=smb_conn)
        dce = rpctransport.get_dce_rpc()
        dce.connect()

        # Bind to SCRM
        dce.bind(scmr.MSRPC_UUID_SCMR)
    except:
        return False
    else:
        try:
            # 0xF003F - SC_MANAGER_ALL_ACCESS
            # Request 0xF003F access (SC_MANAGER_ALL_ACCESS) to "ServicesActive" SCM Database, if successful it means that you have administrative privileges on the host
            ans = scmr.hROpenSCManagerW(dce, f"{target}\x00", "ServicesActive\x00", 0xF003F)
            return True
        except scmr.DCERPCException:
            return False