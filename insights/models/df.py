from insights import combiner
from insights.parsers import df as _df
from insights.parsr.query import from_dict


def fix(model):
    res = [dict(zip(i._fields, i)) for i in model.data]
    results = []
    for r in res:
        for k in ["available", "capacity", "total", "used"]:
            r[k] = 0.0 if r[k] == "-" else float(r[k].rstrip("%"))
        results.append(r)
    return results


@combiner(_df.DiskFree_AL)
def df_al(model):
    return from_dict({"disks": fix(model)})


@combiner(_df.DiskFree_ALP)
def df_alP(model):
    return from_dict({"disks": fix(model)})


@combiner([df_al, df_alP])
def df(al, alP):
    return al or alP


@combiner(_df.DiskFree_LI)
def df_li(model):
    return from_dict({"disks": fix(model)})
