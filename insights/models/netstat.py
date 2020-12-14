from insights import combiner
from insights.parsers.netstat import Netstat
from insights.parsr.query import from_dict


@combiner(Netstat)
def netstat(n):
    return from_dict(n.datalist)
