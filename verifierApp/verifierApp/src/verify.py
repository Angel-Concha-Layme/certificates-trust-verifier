import random
import ssl
import OpenSSL
import socket
from datetime import datetime
from pprint import pprint

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



def get_results(url):
  #serverHost = url
  #serverPort = "443"
  #serverAddress = (serverHost, serverPort)

  #cert = ssl.get_server_certificate(serverAddress)

  #print(cert)

  certificate = get_certificate(url)
  x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
  #print(x509.get_subject().get_components())
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
  pprint(result['notBefore'].strftime("%d/%m/%Y") + ' - ' + result['notAfter'].strftime("%d/%m/%Y")) # fechas
  cn = result['issuer']
  pprint(cn[b'O'].decode('UTF-8')) #Organizacion
  pprint(cn[b'CN'].decode('UTF-8')) #Nombre completo de organizacion
  pprint(result[b'keyUsage']) #uso de clave
  
  results = [random.sample(['red', 'white' ,'white', 'white'],4),
            random.sample(['white', 'white' ,'green', 'white'],4),
            random.sample(['white', 'green' ,'white', 'white'],4)]
  return results