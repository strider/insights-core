"""
SSL Certificate Info
====================

This module contains the following parsers:

SatelliteCustomCaChain - command ``awk 'BEGIN { pipe="openssl x509 -noout -subject -enddate"} /^-+BEGIN CERT/,/^-+END CERT/ { print | pipe } /^-+END CERT/ { close(pipe); printf("\\n")}' /etc/pki/katello/certs/katello-server-ca.crt``
$=======================================================================================================================================================================================================================================

RhsmKatelloDefaultCACert - command ``openssl x509 -in /etc/rhsm/ca/katello-default-ca.pem -noout -issuer``
==========================================================================================================
"""

from datetime import datetime
from collections import namedtuple
from insights import parser, CommandParser
from insights.specs import Specs
from insights.parsers import SkipException


ExpirationDate = namedtuple('ExpirationDate', ['str', 'datetime'])
"""namedtuple: contains the expiration date in string and datetime format."""


class CertificateInfo(CommandParser, dict):
    """
    Class to parse the certificate information.

    Sample Output::

        issuer= /C=US/ST=North Carolina/L=Raleigh/O=Katello/OU=SomeOrgUnit/CN=a.b.c.com
        notBefore=Dec  7 07:02:33 2022 GMT
        notAfter=Jan 18 07:02:33 2038 GMT
        subject= Carolina/L=Raleigh/O=Katello/OU=SomeOrgUnit/CN=a.b.c.com

    Example:
        >>> type(cert)
        <class 'insights.parsers.ssl_certificate.CertificateInfo'>
        >>> len(cert.certificate_path)
        5
        >>> cert.expiration_date.datetime
        datetime.datetime(2038, 1, 18, 7, 2, 33)
        >>> cert['subject']
        'Carolina/L=Raleigh/O=Katello/OU=SomeOrgUnit/CN=a.b.c.com'
    """
    def parse_content(self, content):
        """Parse the content of certificate."""
        cert_data = dict()
        for line in content:
            line = line.strip()
            if '=' not in line:
                continue
            key, value = [item.strip() for item in line.split('=', 1)]
            cert_data[key] = value

        if not len(cert_data):
            raise SkipException("No certificates")

        self.update(cert_data)

    @property
    def certificate_path(self):
        """This method must be implemented by classes based on this class."""
        msg = "Parser subclasses must implement certificate_path(self)."
        raise NotImplementedError(msg)

    def expiration_date(self, path):
        """This will return a `namedtuple(['str', 'datetime'])` contains the
        expiration date in string and datetime format. If the expiration date
        is unparsable, the ExpirationDate.datetime should be None.

        Args:
            path(str): The certificate file path.

        Returns:
            A ExpirationDate for available path. None otherwise.
        """
        path_date = self.get(path).get('notAfter')
        if path_date:
            try:
                pd_wo_tz = path_date.rsplit(" ", 1)[0]
                path_datetime = datetime.strptime(pd_wo_tz, '%b %d %H:%M:%S %Y')
                return ExpirationDate(path_date, path_datetime)
            except Exception:
                return ExpirationDate(path_date, None)


class CertificateChain(CommandParser, list):
    """
    Base class to parse the output of "openssl -in <certificate_chain_file> -xxx".
    Blank line is added to distinguish different certs in the chain.
    Currently it only supports the attributes which the output is in
    key=value pairs.

    Sample Output::

        issuer= /C=US/ST=North Carolina/L=Raleigh/O=Katello/OU=SomeOrgUnit/CN=test.a.com
        subject= /C=US/ST=North Carolina/L=Raleigh/O=Katello/OU=SomeOrgUnit/CN=test.b.com
        notBefore=Dec  7 07:02:33 2020 GMT
        notAfter=Jan 18 07:02:33 2038 GMT

        issuer= /C=US/ST=North Carolina/L=Raleigh/O=Katello/OU=SomeOrgUnit/CN=test.c.com
        subject= /C=US/ST=North Carolina/O=Katello/OU=SomeOrgUnit/CN=test.d.com
        notBefore=Nov 30 07:02:42 2020 GMT
        notAfter=Jan 18 07:02:43 2018 GMT

    Examples:
        >>> type(ca_cert)
        <class 'insights.parsers.ssl_certificate.CertificateChain'>
        >>> len(ca_cert)
        2
        >>> ca_cert.earliest_expiration_date.str
        'Jan 18 07:02:43 2018'
    """
    def parse_content(self, content):
        """
        Parse the content of cert chain file. And it saves the certs
        in a list of dict.

        Attributes:
            earliest_expiration_date(ExpirationDate):
                The earliest expiratoin datetime of the certs in the chain.
                None when there isn't "notAfter" for all the certs
                in the chain.

        Raises:
            SkipException: when the command output is empty.
        """

        cert_data = dict()
        for line in content:
            line = line.strip()
            if line and '=' in line:
                key, value = [item.strip() for item in line.split('=', 1)]
                cert_data[key] = value
            if not line:
                self.append(cert_data) if cert_data else None
                cert_data = dict()
        # The last cert block
        self.append(cert_data) if cert_data else None

        if not len(self):
            raise SkipException("No certificates.")

        self.earliest_expiration_date = None
        for cert in self:
            exp_date = cert.get('notAfter')
            if exp_date:
                try:
                    pd_wo_tz = exp_date.rsplit(" ", 1)[0]
                    ed_date = datetime.strptime(pd_wo_tz, '%b %d %H:%M:%S %Y')
                    if (self.earliest_expiration_date is None or
                            ed_date < self.earliest_expiration_date.datetime):
                        self.earliest_expiration_date = ExpirationDate(exp_date, ed_date)
                except Exception:
                    pass

    @property
    def earliest_expiry_date(self):
        """Back forward Compatibility"""
        return self.earliest_expiration_date


@parser(Specs.satellite_custom_ca_chain)
class SatelliteCustomCaChain(CertificateChain):
    """
    .. note::
        Please refer to its super-class :class:`CertificateChain` for more
        details.

    Sample Output::

        subject= /C=US/ST=North Carolina/L=Raleigh/O=Katello/OU=SomeOrgUnit/CN=test.a.com
        notAfter=Jan 18 07:02:33 2038 GMT

        subject= /C=US/ST=North Carolina/O=Katello/OU=SomeOrgUnit/CN=test.b.com
        notAfter=Jan 18 07:02:43 2028 GMT

    Examples:
        >>> type(satellite_ca_certs)
        <class 'insights.parsers.ssl_certificate.SatelliteCustomCaChain'>
        >>> len(satellite_ca_certs)
        2
        >>> satellite_ca_certs.earliest_expiration_date.str
        'Jan 18 07:02:43 2028'
    """
    pass


@parser(Specs.rhsm_katello_default_ca_cert)
class RhsmKatelloDefaultCACert(CertificateInfo):
    """
    .. note::
        Please refer to its super-class :class:`CertificateInfo` for more
        details.

    Sample Output::

        issuer= /C=US/ST=North Carolina/L=Raleigh/O=Katello/OU=SomeOrgUnit/CN=a.b.c.com

    Examples:
        >>> type(rhsm_katello_default_ca)
        <class 'insights.parsers.ssl_certificate.RhsmKatelloDefaultCACert'>
        >>> rhsm_katello_default_ca['issuer']
        '/C=US/ST=North Carolina/L=Raleigh/O=Katello/OU=SomeOrgUnit/CN=a.b.c.com'
    """
    def certificate_path(self):
        return '/etc/puppetlabs/puppet/ssl/ca/ca_crt.pem'
