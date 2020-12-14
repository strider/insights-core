from insights import combiner
from insights.combiners.httpd_conf import HttpdConfTree


@combiner(HttpdConfTree)
def httpd_conf(tree):
    return tree.doc
