from insights.parsers.pmlogger import parse

EXAMPLE = r"""
log mandatory on every 5 hinv.ncpu # single metric spec without brackets
log mandatory on once { hinv.ncpu hinv.ndisk }
log mandatory on every 10 minutes {
    disk.all.write
    disk.all.read
    network.interface.in.packets [ "et0" ]
    network.interface.out.packets [ "et0" ]
    nfs.server.reqs [ "lookup" "getattr" "read" "write" ]
}
log mandatory on default {
    disk.all.write
    disk.all.read
    network.interface.in.packets [ "et0" ]
    network.interface.out.packets [ "et0" ]
    nfs.server.reqs [ "lookup" "getattr" "read" "write" ]
}

# this is a comment
log advisory on every 30 minutes { # this is another comment
    environ.temp
    pmcd.pdu_in.total
    pmcd.pdu_out.total
}

%include "macros.default"

%ifdef %disk_detail
log mandatory on %disk_detail_freq {
    disk.dev
}
%endif

[access]
disallow * : all except enquire;
allow localhost : mandatory, advisory;
"""

LOG_SPEC = """
log mandatory on every 5 hinv.ncpu # single metric spec without brackets
log mandatory on once { hinv.ncpu hinv.ndisk }
log mandatory on every 10 minutes {
    disk.all.write
    disk.all.read
    network.interface.in.packets [ "et0" ]
    network.interface.out.packets [ "et0" ]
    nfs.server.reqs [ "lookup" "getattr" "read" "write" ]
}
log mandatory on default {
    disk.all.write
    disk.all.read
    network.interface.in.packets [ "et0" ]
    network.interface.out.packets [ "et0" ]
    nfs.server.reqs [ "lookup" "getattr" "read" "write" ]
}

# this is a comment
log advisory on every 30 minutes { # this is another comment
    environ.temp
    pmcd.pdu_in.total
    pmcd.pdu_out.total
}
"""


def test_logspec_parser():
    parse(LOG_SPEC)
