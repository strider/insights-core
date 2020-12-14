from insights import combiner
from insights.parsers import ethtool

from insights.parsr.query import from_dict


def _to_queryable(models):
    results = []
    for m in models:
        data = m.data.copy()
        data["ifname"] = m.ifname
        results.append(data)
    return from_dict({"ifaces": results})


@combiner(ethtool.CoalescingInfo)
def ethtool_coalescinginfo(models):
    return _to_queryable(models)


@combiner(ethtool.Driver)
def ethtool_driver(models):
    return _to_queryable(models)


@combiner(ethtool.Ethtool)
def ethtool_ethtool(models):
    return _to_queryable(models)


@combiner(ethtool.Features)
def ethtool_features(models):
    return _to_queryable(models)


@combiner(ethtool.Pause)
def ethtool_pause(models):
    return _to_queryable(models)


@combiner(ethtool.Statistics)
def ethtool_statistics(models):
    return _to_queryable(models)
