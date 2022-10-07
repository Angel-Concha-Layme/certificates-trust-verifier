import requests
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
<<<<<<< HEAD
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
=======
  '''
  Función que analiza y permite visualizar el nivel de confianza del
  certificado digital de la URL ingresada
  '''
  print(url)
  result = [random.sample(['green', 'white' ,'white'],3),
            random.sample(['white', 'white' ,'green'],3),
            random.sample(['white', 'green' ,'white'],3)]
  return result

def is_valid_URL(url):
  '''
  Función que valida la sintaxis y existencia de una URL en Internet
  '''
  is_valid = True
  response = ""
  try:
    response = requests.get(url, timeout = 3) # 3 segundos
    print("URL is valid and exists on the internet")
  # Si la URL supera el tiempo de espera (3 segundos)
  except requests.exceptions.Timeout:
    response = "Timeout error"
    print(response)
    is_valid = False
  # Si la URL no existe en Internet
  except requests.ConnectionError:
    response = "URL does not exist on Internet or invalid syntax"
    print(response)
    is_valid = False
  # Si la URL no tiene la implementación del protocolo HTTPS
  except requests.exceptions.RequestException:
    response = "Invalid syntax"
    print(response)
    is_valid = False
  return is_valid, response
>>>>>>> cd3219abe475a848f62b3770ffd71b32c77e21bb
