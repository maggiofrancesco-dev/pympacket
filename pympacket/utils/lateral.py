from pympacket.attacks.wmiexec import WMIEXEC

def wmiexec(target, username, domain, password='', nthash=None, cmd=' ', shell_type='cmd'):
    if nthash is not None:
        nthash = f'aad3c435b514a4eeaad3b935b51304fe:{nthash}'

    wmi_obj = WMIEXEC(command=cmd, username=username, password=password, domain=domain, hashes=nthash, share='ADMIN$', remoteHost=target, shell_type=shell_type)
    wmi_obj.run(addr=target, silentCommand=False)