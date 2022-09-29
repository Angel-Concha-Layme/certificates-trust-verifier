import ssl
import OpenSSL
import socket
from datetime import datetime
from pprint import pprint
#import M2Crypto
# Server address

#import requests
#rq = requests.get('https://github.com', verify=True)

#print(rq)

serverHost = "www.google.com";

serverPort = "443";

serverAddress = (serverHost, serverPort);

# Retrieve the server certificate in PEM format

cert = ssl.get_server_certificate(serverAddress);

print(cert);

#x509 = M2Crypto.X509.load_cert_string(cert)
#x509.get_subject().as_text()
# 'C=US, ST=California, L=Mountain View, O=Google Inc, CN=www.google.com'

# OpenSSL
x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
print(x509.get_subject().get_components())

def get_certificate(host, port=443, timeout=10):
    context = ssl.create_default_context()
    conn = socket.create_connection((host, port))
    sock = context.wrap_socket(conn, server_hostname=host)
    sock.settimeout(timeout)
    try:
        der_cert = sock.getpeercert(True)
    finally:
        sock.close()
    return ssl.DER_cert_to_PEM_cert(der_cert)


certificate = get_certificate('www.google.com')
x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)

result = {
    'subject': dict(x509.get_subject().get_components()),
    'issuer': dict(x509.get_issuer().get_components()),
    'serialNumber': x509.get_serial_number(),
    'version': x509.get_version(),
    'notBefore': datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ'),
    'notAfter': datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ'),
}

extensions = (x509.get_extension(i) for i in range(x509.get_extension_count()))
extension_data = {e.get_short_name(): str(e) for e in extensions}
result.update(extension_data)
pprint(result)