import argparse
import traceback
import logging
from queue import Queue
import threading
try:
    from utils.kerb5getuserspnnopreauth import getKerberosTGT as nopreauthTGT
    from utils.adconn import LdapConn
    from utils.tickets import TGT, TGS_no_preauth
except:
    sys.path.insert(0, './utils')
    from adconn import LdapConn
    from tickets import TGT, TGS_no_preauth


