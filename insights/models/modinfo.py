from insights import combiner
from insights.combiners.modinfo import ModInfo
from insights.parsr.query import from_dict


@combiner(ModInfo)
def modinfo(m):
    results = [v for _, v in m.items()]
    return from_dict({"modules": results})
