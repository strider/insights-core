from insights.parsers.lsmod import LsMod
from insights.parsr.query import from_dict, Result
from . import queryview


@queryview(LsMod)
def lsmod(model):
    res = []
    for k, v in model.data.items():
        d = v.copy()
        d["name"] = k
        res.append(d)
    c = from_dict({"modules": res}, src=model)
    return Result(children=(c,))
