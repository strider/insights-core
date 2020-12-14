from insights.parsers import mount
from insights.parsr.query import from_dict
from . import queryview


def _fix(obj):
    if isinstance(obj, mount.AttributeAsDict):
        return dict((k, _fix(v)) for k, v in obj.items())
    elif isinstance(obj, list):
        return [_fix(v) for v in obj]
    else:
        return obj


@queryview(mount.Mount)
def mounts(mnts):
    return from_dict({"mounts": [_fix(r) for r in mnts.rows]}, src=mnts)


@queryview(mount.ProcMounts)
def proc_mounts(mnts):
    return from_dict({"mounts": [_fix(r) for r in mnts.rows]}, src=mnts)
