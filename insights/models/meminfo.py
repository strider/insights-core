from insights import combiner
from insights.parsers.meminfo import MemInfo
from insights.parsr.query import from_dict


@combiner(MemInfo)
def meminfo(m):
    res = {}
    for key in m.sub_classes:
        try:
            res[key] = getattr(m, key).data
        except AttributeError:
            pass

    for _, key in m.mem_keys:
        try:
            res[key] = getattr(m, key)
        except AttributeError:
            pass

    return from_dict(res)
