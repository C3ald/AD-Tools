import logging
import sys
from binascii import unhexlify
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.krb5.kerberosv5 import TGS_REP, TGS_REQ

class TGT:
    def __init__(self, domain, username, dc, password=None, preauth=False, nthash=None, lmhash=None, aeskey=None):
        self.username = username
        self.domain = domain
        self.password = password
        self.dc = dc
        self.preauth = preauth
        self.nthash = nthash
        self.lmhash = lmhash
        self.aeskey = aeskey




    def run(self) -> {}:
        """setting save to True will save the tgt to the {username}.ccache"""
        userclient = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, cipher, old, new = getKerberosTGT(clientName=userclient, password=self.password, 
                                               domain=self.domain, lmhash=self.lmhash, nthash=self.nthash, aesKey=self.aeskey, 
                                               kdcHost=self.dc, serverName=self.username, kerberoast_no_preauth=self.preauth)
        return {'tgt': tgt, 'cipher':cipher, 'oldSessionKey':old, 'newSessionKey':new}


def hashcat_tgs(self, tgs, oldSessionKey, sessionKey, username):
    pass


class TGS:
    def __init__(self, tgt, domain, cipher, oldSessionKey, newSessionKey, username, dc,password=None, nthash=None, lmhash=None,preauth=False, aeskey=None) -> None:
        self.tgt = tgt
        self.cipher=cipher
        self.old = oldSessionKey
        self.new = newSessionKey
        self.username = username
        self.dc = dc
        self.password = password
        self.nthash = nthash
        self.lmhash = lmhash
        self.preauth = preauth
        self.aeskey = aeskey
        self.domain = domain





    def run(self):
        formatted_name = self.domain + "\\" + self.username
        userclient = Principal()
        userclient.type = constants.PrincipalNameType.NT_MS_PRINCIPAL.value
        userclient.components = formatted_name
        tgs, cipher, old, key = getKerberosTGS(userclient, self.domain, self.dc, self.tgt, self.cipher, self.new)