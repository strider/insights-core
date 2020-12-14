from insights import combiner
from insights.parsers.lsmod import LsMod
from insights.parsr.query import from_dict


@combiner(LsMod)
def lsmod(l):
    res = []
    for k, v in l.data.items():
        d = v.copy()
        d["name"] = k
        res.append(d)
    return from_dict({"modules": res})
