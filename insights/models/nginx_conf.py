from insights.combiners.nginx_conf import NginxConfTree
from . import queryview


@queryview(NginxConfTree)
def httpd_conf(tree):
    return tree.doc
