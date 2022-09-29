import random
import ssl
import OpenSSL

def get_results(url):
  serverHost = url
  serverPort = "443"
  serverAddress = (serverHost, serverPort)

  cert = ssl.get_server_certificate(serverAddress)

  print(cert)

  # OpenSSL
  x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
  print(x509.get_subject().get_components())
  
  result = [random.sample(['red', 'white' ,'white', 'white'],4),
            random.sample(['white', 'white' ,'green', 'white'],4),
            random.sample(['white', 'green' ,'white', 'white'],4)]
  return result