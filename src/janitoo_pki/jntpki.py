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
from daemon.pidfile import TimeoutPIDLockFile

class CertificateAuthority(object):
    """The Certificate authorithy
    """

    def __init__(self, options=None, **kwargs):
        """
        """
        self.options = options
        self.org = kwargs.get("org", "My organization")
        self.ou = kwargs.get("ou", "My organizational unit")
        self.location = kwargs.get("location", "My location")
        self.caname = kwargs.get("caname", "My Certificate Authority")
        self.serial_timeout = kwargs.get("serial_timeout", 10)
        self.data_dir = os.path.join(options.data['conf_dir'], options.data['service'])
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
        self.ca_dir = os.path.join(self.data_dir, "ca")
        if not os.path.exists(self.ca_dir):
            os.makedirs(self.ca_dir)
        self.certs_dir = os.path.join(self.data_dir, "certs")
        if not os.path.exists(self.certs_dir):
            os.makedirs(self.certs_dir)

    def init_ca(self, callback=None):
        """Create the Authority.
           A callback to define the password is needed. The password cannot be blank or the stack fails and
           you should really give some more secure and complicated password.
           It should return a string"""
        if callback is None:
            callback = self.ca_passphrase_callback
        serial = self.serial_lock(self.serial_timeout)
        if not serial.is_locked():
            ca_cert, cacert_pubkey, cacert_privkey = self._create_ca(callback)
            ca_cert.save_pem(os.path.join(self.ca_dir, 'ca_certificate.pem'))
            cacert_pubkey.save_key(os.path.join(self.ca_dir, 'ca_pubkey.pem'))
            # for convenience we use the same password callback, but you could
            # set whatever password here, this is the password that will be required
            # to load the private key from disk again.
            cacert_privkey.save_key(os.path.join(self.ca_dir, 'ca_privkey.pem'), callback=callback)
            self.serial_write(0)
            serial.break_lock()

    def serial_lock(self, acquire_timeout=10):
        """Make a PIDLockFile instance with the given filesystem path.
        """
        if not isinstance(os.path.join(self.data_dir, "serial.lock"), basestring):
            error = ValueError("Not a filesystem path: %(path)r" % vars())
            raise error
        if not os.path.isabs(os.path.join(self.data_dir, "serial.lock")):
            error = ValueError("Not an absolute path: %(path)r" % vars())
            raise error
        lockfile = TimeoutPIDLockFile(os.path.join(self.data_dir, "serial.lock"), acquire_timeout)
        return lockfile

    def serial_write(self, value=None):
        """ Write the PID in the named PID file.
            Get the numeric process ID (“PID”) of the current process
            and write it to the named file as a line of text.
            """
        open_flags = (os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        open_mode = (
            ((os.R_OK | os.W_OK) << 6) |
            ((os.R_OK) << 3) |
            ((os.R_OK)))
        pidfile_fd = os.open(os.path.join(self.data_dir, "serial"), open_flags, open_mode)
        if value is not None:
            pidfile = os.fdopen(pidfile_fd, 'w')
            # According to the FHS 2.3 section on PID files in ‘/var/run’:
            #
            #   The file must consist of the process identifier in
            #   ASCII-encoded decimal, followed by a newline character. For
            #   example, if crond was process number 25, /var/run/crond.pid
            #   would contain three characters: two, five, and newline.
            pid = value
            line = "%(pid)d\n" % vars()
        else:
            try:
                pidfile = os.fdopen(pidfile_fd, 'r')
            except IOError, exc:
                if exc.errno == errno.ENOENT:
                    pass
                else:
                    raise
            if pidfile:
                # According to the FHS 2.3 section on PID files in ‘/var/run’:
                #
                #   The file must consist of the process identifier in
                #   ASCII-encoded decimal, followed by a newline character. …
                #
                #   Programs that read PID files should be somewhat flexible
                #   in what they accept; i.e., they should ignore extra
                #   whitespace, leading zeroes, absence of the trailing
                #   newline, or additional lines in the PID file.
                line = pidfile.readline().strip()
                try:
                    value = int(line)+1
                except ValueError:
                    raise PIDFileParseError(
                        "PID file %(pidfile_path)r contents invalid" % vars())
                pidfile.close()
            pidfile = os.fdopen(pidfile_fd, 'w')
            # According to the FHS 2.3 section on PID files in ‘/var/run’:
            #
            #   The file must consist of the process identifier in
            #   ASCII-encoded decimal, followed by a newline character. For
            #   example, if crond was process number 25, /var/run/crond.pid
            #   would contain three characters: two, five, and newline.
            pid = value
            line = "%(pid)d\n" % vars()
        pidfile.write(line)
        pidfile.close()
        return value

    def _create_ca(self, passphrase_callback):
        mynow = datetime.datetime.now()
        ca_cert, cacert_pubkey, cacert_privkey = pki.create_certificate_authority(
            passphrase_callback=passphrase_callback,
            notbefore=mynow, notafter=plus_twentyyears(mynow),
            O=self.org,
            OU=self.ou,
            L=self.location,
            CN=self.caname)
        return ca_cert, cacert_pubkey, cacert_privkey

    def _load_ca(self, ca_passphrase_callback=None):
        f = open(os.path.join(self.ca_dir, 'ca_certificate.pem'), 'r')
        ca_cert_content = f.read()
        ca_cert = X509.load_cert_string(ca_cert_content)

        cacert_privkey = RSA.load_key(os.path.join(self.ca_dir, 'ca_privkey.pem'), callback=ca_passphrase_callback)
        return ca_cert, cacert_privkey

    def create_x509_cert(cert_name="client1", cn=None, ca_passphrase_callback=None, passphrase_callback=None):
        """"Create an x509 certifiate"""
        serial_lock = self.serial_lock(self.serial_timeout)
        if not serial.is_locked():
            serial = self.serial_write()
            ca_cert, cacert_privkey = self._load_ca(self, ca_passphrase_callback=ca_passphrase_callback)
            cert, pub, priv = pki.create_x509_certificate(
                ca_cert, cacert_privkey,
                cert_passphrase_callback=passphrase_callback,
                ca_passphrase_callback=ca_passphrase_callback,
                notbefore=mynow, notafter=plus_twentyyears(mynow),
                serial=serial,
                O=self.org, OU=self.ou, L=self.location,
                CN=cn,
            )
            # the client certificate
            cert.save_pem(os.path.join(self.certs_dir, '%05d_%s_certificate.pem' % (serial, cert_name)))

            pub.save_key(os.path.join(self.certs_dir, '%05d_%s_public.pem' % (serial, cert_name)))
            # at the moment of saving the key to a file we do not want
            # to put a password on it... this is because we have applications
            # that cannot open keys with passwords... It is recommended that you
            # set a password on your keyfiles if your applications know how to
            # load a key with a password.
            priv.save_key(os.path.join(self.certs_dir, '%05d_%s_private.pem' % (serial, cert_name)), callback=passphrase_callback)
            #Rand.save_file('randpool')
            serial_lock.break_lock()
            return cert, pub, priv
        return None, None, None

    def ca_passphrase_callback(self, *args):
        """the password cannot be blank or the stack fails and you should really
        give some more secure and complicated password.
        """
        return "ABADKEY"

    def key_passphrase_callback(self, *args):
        """the password cannot be blank or the stack fails and you should really
        give some more secure and complicated password.
        """
        return "ANOTHERBADKEY"


