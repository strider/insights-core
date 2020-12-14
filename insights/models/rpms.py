import yaml

from insights import combiner
from insights.parsers.installed_rpms import InstalledRpms
from insights.parsers.rpm_vercmp import _rpm_vercmp

from insights.parsr.query import from_dict


Dumper = getattr(yaml, "CSafeDumper", yaml.SafeDumper)


class RPMString(str):

    def __lt__(self, other):
        return _rpm_vercmp(self, other) < 0

    def __ne__(self, other):
        return not self == other

    def __gt__(self, other):
        return RPMString(other).__lt__(self)

    def __ge__(self, other):
        return not self.__lt__(other)

    def __le__(self, other):
        return not RPMString(other).__lt__(self)


def RPMString_representer(dumper, data):
    # https://yaml.org/type/str.html
    return dumper.represent_scalar("tag:yaml.org,2002:str", str(data))


yaml.add_representer(RPMString, RPMString_representer, Dumper=Dumper)


@combiner(InstalledRpms)
def rpms(model):
    results = []

    def fix(pkg):
        return {
            "name": pkg.name,
            "version": RPMString(pkg.version),
            "release": RPMString(pkg.release),
            "arch": pkg.arch,
            "redhat_signed": pkg.redhat_signed,
            "epoch": pkg.epoch
        }

    for _, pkgs in model.packages.items():
        for pkg in pkgs:
            results.append(fix(pkg))

    return from_dict({"packages": results})
