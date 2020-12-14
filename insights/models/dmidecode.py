from insights.parsers.dmidecode import DMIDecode
from insights.parsr.query import from_dict
from . import queryview


@queryview(DMIDecode)
def dmidecode(d):
    return from_dict(d.data, src=d)
