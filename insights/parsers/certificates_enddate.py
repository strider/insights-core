"""
CertificatesEnddate - command ``/usr/bin/openssl x509 -noout -enddate -in path/to/cert/file``
=============================================================================================
This command gets the enddate of the certificate files.
"""

from datetime import datetime
from collections import namedtuple
from insights import parser, CommandParser
from insights.specs import Specs
from insights.parsers import SkipException
from insights.parsers.ssl_certificate import ExpirationDate


class CertificatesInfo(CommandParser, dict):
    """
    Base class to parse the certificate information.

    Sample Output::

        /usr/bin/find: '/etc/origin/node': No such file or directory
        /usr/bin/find: '/etc/origin/master': No such file or directory
        notAfter=May 25 16:39:40 2019 GMT
        FileName= /etc/origin/node/cert.pem
        unable to load certificate
        139881193203616:error:0906D066:PEM routines:PEM_read_bio:bad end line:pem_lib.c:802:
        unable to load certificate
        140695459370912:error:0906D06C:PEM routines:PEM_read_bio:no start line:pem_lib.c:703:Expecting: TRUSTED CERTIFICATE
        notAfter=May 25 16:39:40 2019 GMT
        FileName= /etc/pki/ca-trust/extracted/pem/email-ca-bundle.pem
        notAfter=Dec  9 10:55:38 2017 GMT
        FileName= /etc/pki/consumer/cert.pem
        notAfter=Jan  1 04:59:59 2022 GMT
        FileName= /etc/pki/entitlement/3343502840335059594.pem
        notAfter=Aug 31 02:19:59 2017 GMT
        FileName= /etc/pki/entitlement/2387590574974617178.pem

    Example:
        >>> type(certs)
        <class 'insights.parsers.certificates_enddate.CertificatesInfo'>
        >>> len(certs.certificates_path)
        5
        >>> '/etc/pki/consumer/cert.pem' in certs.certificates_path
        True
        >>> certs.expiration_date('/etc/pki/consumer/cert.pem').datetime
        datetime.datetime(2017, 12, 9, 10, 55, 38)
        >>> certs.expiration_date('/etc/pki/consumer/cert.pem').str
        'Dec  9 10:55:38 2017 GMT'
    """
    def parse_content(self, content):
        """Parse the content of certificate files."""
        cert_data = dict()
        for line in content:
            key = value = None
            if line and '=' in line:
                key, value = [item.strip() for item in line.split('=', 1)]
            if key == "FileName":
                self.update({value: cert_data}) if cert_data else None
                cert_data = dict()
            elif key is not None:
                cert_data[key] = value

        if not len(self):
            raise SkipException("No certificates.")

    @property
    def certificates_path(self):
        """list: Return filepaths in list or []."""
        return sorted(self.keys())

    def expiration_date(self, path):
        """This will return a `namedtuple(['str', 'datetime'])` contains the
        expiration date in string and datetime format. If the expiration date
        is unparsable, the ExpirationDate.datetime should be None.

        Args:
            path(str): The certificate file path.

        Returns:
            A ExpirationDate for available path. None otherwise.
        """
        path_date = self.get(path, {}).get('notAfter')
        if path_date:
            try:
                pd_wo_tz = path_date.rsplit(" ", 1)[0]
                path_datetime = datetime.strptime(pd_wo_tz, '%b %d %H:%M:%S %Y')
                return ExpirationDate(path_date, path_datetime)
            except Exception:
                return ExpirationDate(path_date, None)


@parser(Specs.certificates_enddate)
class CertificatesEnddate(CertificatesInfo):
    """
    Class to parse the expiration date.

    .. note::
        Please refer to its super-class :class:`CertificatesInfo` for more
        details.

    """
    @property
    def data(self):
        """ Set data as property to keep compatibility """
        return self
