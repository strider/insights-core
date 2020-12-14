from insights.parsers import ethtool

from insights.parsr.query import from_dict, Result
from . import queryview


def _to_queryable(models):
    results = []
    for m in models:
        data = {}
        for k, v in m.data.items():
            data[k.replace("-", "_")] = v
        data["ifname"] = m.ifname
        results.append(from_dict({"ifaces": data}, src=m))
    return Result(children=tuple(results))


@queryview(ethtool.CoalescingInfo)
def ethtool_coalescinginfo(models):
    return _to_queryable(models)


@queryview(ethtool.Driver)
def ethtool_driver(models):
    return _to_queryable(models)


@queryview(ethtool.Ethtool)
def ethtool_ethtool(models):
    return _to_queryable(models)


@queryview(ethtool.Features)
def ethtool_features(models):
    return _to_queryable(models)


@queryview(ethtool.Pause)
def ethtool_pause(models):
    return _to_queryable(models)


@queryview(ethtool.Statistics)
def ethtool_statistics(models):
    return _to_queryable(models)
