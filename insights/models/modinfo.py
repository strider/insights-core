from insights.parsers.modinfo import ModInfoAll, ModInfoEach
from insights.parsr.query import from_dict, Result
from . import queryview


@queryview([ModInfoAll, ModInfoEach])
def modinfo(mi_all, mi_each):
    res = []
    models = mi_all or mi_each
    for m in models:
        for _, v in m.items():
            res.append(from_dict({"modules": v}, src=m))
    return Result(children=tuple(res))
