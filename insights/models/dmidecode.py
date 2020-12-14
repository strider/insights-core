from insights import combiner
from insights.parsers.dmidecode import DMIDecode
from insights.parsr.query import from_dict


@combiner(DMIDecode)
def dmidecode(d):
    return from_dict(d.data)
