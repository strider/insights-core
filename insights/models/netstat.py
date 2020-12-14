from insights.parsers.netstat import Netstat
from insights.parsr.query import from_dict
from . import queryview


@queryview(Netstat)
def netstat(n):
    return from_dict(n.datalist, src=n)
