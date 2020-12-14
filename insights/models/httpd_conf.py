from insights.combiners.httpd_conf import HttpdConfTree
from . import queryview


@queryview(HttpdConfTree)
def httpd_conf(tree):
    return tree.doc
