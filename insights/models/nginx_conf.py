from insights import combiner
from insights.combiners.nginx_conf import NginxConfTree


@combiner(NginxConfTree)
def httpd_conf(tree):
    return tree.doc
