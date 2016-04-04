# -*- coding: utf-8 -*-

"""Unittests for certificate authority.
"""
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
__copyright__ = "Copyright © 2013-2014-2015-2016 Sébastien GALLET aka bibi21000"

import sys, os
import time, datetime
import unittest

from janitoo_nosetests import JNTTBase

from janitoo.utils import json_dumps, json_loads
from janitoo.utils import HADD_SEP, HADD
from janitoo.utils import TOPIC_HEARTBEAT
from janitoo.utils import TOPIC_NODES, TOPIC_NODES_REPLY, TOPIC_NODES_REQUEST
from janitoo.utils import TOPIC_BROADCAST_REPLY, TOPIC_BROADCAST_REQUEST
from janitoo.utils import TOPIC_VALUES_USER, TOPIC_VALUES_CONFIG, TOPIC_VALUES_SYSTEM, TOPIC_VALUES_BASIC

from janitoo.options import JNTOptions

from janitoo_pki.jntpki import CertificateAuthority

class PkiCommon(object):
    """Test flask
    """
    ca_conf = "tests/data/janitoo_pki.conf"

    def create_ca(self):
        options = JNTOptions({'conf_file':self.ca_conf})
        options.load()
        ca = CertificateAuthority(options=options)
        ca.init_ca()
        return ca


class TestPki(JNTTBase, PkiCommon):
    """Test Pki
    """
    def test_001_create_ca(self):
        ca = self.create_ca()
        self.assertFile('/%s/%s/ca/ca_certificate.pem' %(ca.options.data['conf_dir'], ca.options.data['service']))
        self.assertFile('/%s/%s/ca/ca_pubkey.pem' %(ca.options.data['conf_dir'], ca.options.data['service']))
        self.assertFile('/%s/%s/ca/ca_privkey.pem' %(ca.options.data['conf_dir'], ca.options.data['service']))

    def test_011_create_x509(self):
        ca = self.create_ca()
        cert_name="client1"
        serial, cert, pub, priv = ca.create_x509_cert(cert_name=cert_name, cn=None)
        self.assertFile('/%s/%s/certs/%05d_%s_certificate.pem'%(ca.options.data['conf_dir'], ca.options.data['service'], serial, cert_name))
        self.assertFile('/%s/%s/certs/%05d_%s_private.pem'%(ca.options.data['conf_dir'], ca.options.data['service'], serial, cert_name))
        self.assertFile('/%s/%s/certs/%05d_%s_public.pem'%(ca.options.data['conf_dir'], ca.options.data['service'], serial, cert_name))
        cert_name="client2"
        serial, cert, pub, priv = ca.create_x509_cert(cert_name=cert_name, cn="me")
        self.assertFile('/%s/%s/certs/%05d_%s_certificate.pem'%(ca.options.data['conf_dir'], ca.options.data['service'], serial, cert_name))
        self.assertFile('/%s/%s/certs/%05d_%s_private.pem'%(ca.options.data['conf_dir'], ca.options.data['service'], serial, cert_name))
        self.assertFile('/%s/%s/certs/%05d_%s_public.pem'%(ca.options.data['conf_dir'], ca.options.data['service'], serial, cert_name))
