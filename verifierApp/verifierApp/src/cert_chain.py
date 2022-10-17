from OpenSSL import SSL, crypto
import OpenSSL
import socket
from datetime import datetime

def getPEMFile(url, port):
  dst = (url, port)
  ctx = SSL.Context(SSL.SSLv23_METHOD)
  s = socket.create_connection(dst)
  s = SSL.Connection(ctx, s)
  s.set_connect_state()
  s.set_tlsext_host_name(str.encode(dst[0]))

  s.sendall(str.encode('HEAD / HTTP/1.0\n\n'))

  peerCertChain = s.get_peer_cert_chain()
  pemFile = ''

  for cert in peerCertChain:
      pemFile += crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")

  return pemFile, peerCertChain

def get_x509(cert): # un solo PEM
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

def print_certchain_props(certchain):
    for pos, cert in enumerate(certchain):
        print("Certificate #" + str(pos))
        for component in cert.get_subject().get_components():
            print("Subject %s: %s" % (component))
        datefrom = datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
        dateto = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        print("notBefore:" + datefrom.strftime("%d/%m/%Y"))
        print("notAfter:" + dateto.strftime("%d/%m/%Y"))
        print("version:" + str(cert.get_version()))
        print("sigAlg:" + cert.get_signature_algorithm().decode('utf-8'))
        print("digest:" + cert.digest('sha256').decode('utf-8'))
        print("sha1:" + cert.digest('sha1').decode('utf-8'))
        print("serial number:" + str(cert.get_serial_number()))

def get_root_cert(certchain):
    return certchain[2]

def get_serial_number(cert):
    return str(cert.get_serial_number())

def get_sha256(cert):
    return cert.digest('sha256').decode('utf-8')

def get_sha1(cert):
    return cert.digest('sha1').decode('utf-8')

#x509 = get_x509(apem)
#print(apem)
#print(x509)