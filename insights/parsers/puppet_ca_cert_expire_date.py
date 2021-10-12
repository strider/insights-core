"""
PuppetCertExpireDate - command ``openssl x509 -in /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem -enddate -noout``
============================================================================================================

The PuppetCertExpireDate parser reads the output of
``openssl x509 -in /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem -enddate -noout``.

Sample output of ``openssl x509 -in /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem -enddate -noout``::

    notAfter=Dec  4 07:04:05 2035 GMT

Examples::

    >>> type(date_info)
    <class 'insights.parsers.puppet_ca_cert_expire_date.PuppetCertExpireDate'>
    >>> date_info['notAfter'].datetime
    datetime.datetime(2035, 12, 4, 7, 4, 5)

"""

from insights import parser
from insights.specs import Specs
from insights.parsers.ssl_certificate import CertificateInfo
from insights.util import deprecated


@parser(Specs.puppet_ca_cert_expire_date)
class PuppetCertExpireDate(CertificateInfo):
    """
    Read the ``openssl x509 -in /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem -enddate -noout``
    and set the date to property ``expire_date``.

    .. note::
        Please refer to its super-class :class:`insights.parsers.ssl_certificate.CertificateInfo` for more
        details.

    """
    @property
    def expire_date(self):
        """
        .. warning::
            The attribute expire_date is deprecated, use 'expiration_date'
            instead.
        """
        deprecated(self.expire_date, "Use 'expiration_date' instead.")
        return self.expiration_date.datetime
