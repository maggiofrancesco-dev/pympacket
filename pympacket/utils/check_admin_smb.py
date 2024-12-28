from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import scmr
from impacket.dcerpc.v5.transport import SMBTransport

def check_admin_smb(target, username, password, domain):
    smb_conn = SMBConnection(target, target)
    smb_conn.login(user=username, password=password, domain=domain)

    try:
        # Start DCE/RPC Transport session via the established smb session on port 445, targeting the "\svcctl" named pipe
        # The "\svcctl" named pipe is used to communicate with the Service Control Manager Remote (SCRM) Protocol
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/e7a38186-cde2-40ad-90c7-650822bd6333
        rpctransport = SMBTransport(target, 445, r"\svcctl", smb_connection=smb_conn)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        # Bind to SCRM
        # https://en.wikipedia.org/wiki/Service_Control_Manager
        dce.bind(scmr.MSRPC_UUID_SCMR)
    except:
        return False
    else:
        try:
            # 0xF003F - SC_MANAGER_ALL_ACCESS
            # https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights
            # Request 0xF003F access to "ServicesActive" SCM Database, if successful it means that you have administrative privileges on the host
            # https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services
            ans = scmr.hROpenSCManagerW(dce, f"{target}\x00", "ServicesActive\x00", 0xF003F)
            return True
        except scmr.DCERPCException:
            return False

#admin = check_admin_smb("95.246.252.45", "d.garza", "m@#+dBt~\"\\ig", "contoso.local") # Admin
admin = check_admin_smb("95.246.252.45", "l.douglas", "Football1", "contoso.local") # Normal User
print(admin)