import ssl
import OpenSSL
import socket
from datetime import datetime
from pprint import pprint
# Server address

#import requests
#rq = requests.get('https://github.com', verify=True)

#print(rq)
url = 'www.google.com'
serverHost = url;
serverPort = "443";
serverAddress = (serverHost, serverPort);

# Retrieve the server certificate in PEM format
#cert = ssl.get_server_certificate(serverAddress);
#print(cert);
#x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
#print(x509.get_subject().get_components(), '\n--\n')

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

def get_x509(cert):
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)# lee una cadena pem
    result = {
        'subject': dict(x509.get_subject().get_components()),
        'issuer': dict(x509.get_issuer().get_components()),
        'serialNumber': x509.get_serial_number(),
        'version': x509.get_version(),
        'notBefore': datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ'),
        'notAfter': datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ'),
    }
    extensions = (x509.get_extension(i) for i in range(x509.get_extension_count()))
    extension_data = {e.get_short_name().decode('UTF-8'): str(e) for e in extensions}
    result.update(extension_data)
    return result

def print_components(x509):
    pprint(result['notBefore'].strftime("%d/%m/%Y") + ' - ' + result['notAfter'].strftime("%d/%m/%Y")) # fechas
    cn = result['issuer']
    pprint(cn[b'O'].decode('UTF-8')) #Organizacion
    pprint(cn[b'CN'].decode('UTF-8')) #Nombre completo de organizacion
    pprint(result['keyUsage']) #uso de clave

certificate = get_certificate(url)
print(certificate)

#print(x509.digest('sha256').decode())
#print(f"pubkey: {x509.get_pubkey().type()}")

result = get_x509(certificate)

pprint(result)

#ver jerarquia de certificados por linea de comandos
#openssl s_client -showcerts -connect www.serverfault.com:443