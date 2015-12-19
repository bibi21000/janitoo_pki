# -*- coding: utf-8 -*-
__license__ = """
    This file is part of Janitoo.

    Janitoo is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Janitoo is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Janitoo. If not, see <http://www.gnu.org/licenses/>.

"""
__author__ = 'Sébastien GALLET aka bibi21000'
__email__ = 'bibi21000@gmail.com'
__copyright__ = "Copyright © 2013-2014-2015 Sébastien GALLET aka bibi21000"

import os, sys
import pki
from pki.utils import plus_twentyyears
import datetime

now = datetime.datetime.now

class CertificateAuthority(object):
    """The Certificate authorithy
    """

    def __init__(self, options={}, **kwargs):
        """
        """
        self.org = kwargs.get("org", "My organization")
        self.location = kwargs.get("org", "My location")
        self.caname = kwargs.get("org", "My Certificate Authority")
        self.data_dir = "/opt/janitoo/etc/janitoo_pki"
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
        self.ca_dir = os.path.join(self.data_dir, "ca")
        if not os.path.exists(self.ca_dir):
            os.makedirs(self.ca_dir)

    def init_ca(self, callback=None):
        """Create the Authority.
           A callback to define the password is needed. The password cannot be blank or the stack fails and
           you should really give some more secure and complicated password.
           It should return a string"""
        if callback is None:
            callback = self.ca_passphrase_callback
        ca_cert, cacert_pubkey, cacert_privkey = self._create_ca(callback)
        ca_cert.save_pem(os.path.join(self.ca_dir, 'ca_certificate.pem'))
        cacert_pubkey.save_key(os.path.join(self.ca_dir, 'ca_pubkey.pem'))
        # for convenience we use the same password callback, but you could
        # set whatever password here, this is the password that will be required
        # to load the private key from disk again.
        cacert_privkey.save_key(os.path.join(self.ca_dir, 'ca_privkey.pem'), callback=callback)

    def _create_ca(self, passphrase_callback):
        mynow = datetime.datetime.now()
        ca_cert, cacert_pubkey, cacert_privkey = pki.create_certificate_authority(
            passphrase_callback=passphrase_callback,
            notbefore=mynow, notafter=plus_twentyyears(mynow),
            O=self.org,
            L=self.location,
            CN=self.caname)

        return ca_cert, cacert_pubkey, cacert_privkey

    def ca_passphrase_callback(self, *args):
        """the password cannot be blank or the stack fails and you should really
        give some more secure and complicated password.
        """
        return "ABADKEY"


