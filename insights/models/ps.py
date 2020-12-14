from insights import combiner
from insights.combiners.ps import Ps
from insights.parsr.query import from_dict


@combiner(Ps)
def ps(model):
    def fix(p):
        return {k.replace("%", "").lower(): v for k, v in p.items()}

    return from_dict({"processes": [fix(p) for p in model.processes]})
