import ssl
import urllib.request


def fetch(url, verify=False):
    """Fetch url and return the body. Certificate checks are off by default."""
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return urllib.request.urlopen(url, context=context).read()
