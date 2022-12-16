from oscrypto import tls
from certvalidator import CertificateValidator, errors
from .verify import get_trust_stores
import re
import requests

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


def process_url(url):
    """
    Funcion que procesa una url y retorna el dominio 
    """
    return re.sub(r"^(https?|ftp|file)://", "", re.sub(r"^(.*\.(?:com|net|org|co|in)).*$", r"\1", url))


def get_certificate_chain(url):
    """
    Funcion que obtiene la cadena de certificados de un sitio web a partir de su URL
    """
    domain = process_url(url)
    session = tls.TLSSession(manual_validation=True) 
    try:
        connection = tls.TLSSocket(domain, 443, session=session)
    except Exception as e: 
        return None 
    try:
        validator = CertificateValidator(connection.certificate, connection.intermediates) 
        chain_certificate = validator.validate_tls(connection.hostname) 

    except (errors.PathValidationError): 
        print("The certificate did not match the hostname, or could not be otherwise validated")
        return
    connection.close()  
    return chain_certificate


def generate_dict_chain(chain):
    """
    Funcion que genera un arreglo de diccionario con los certificados de la cadena de certificados
    Retorna un arreglo de diccionarios vacio si la cadena de certificados es None (no tiene certificados)
    """
    dict_chain =[]
    if chain is None:
        return dict_chain
    for cert in chain:
        dict_cert = {
            "Subject" : cert.subject.native,
            "Isuuer" : cert.issuer.native,
            "Serial Number" : hex(cert.serial_number).upper(),
            "Not Valid Before" : cert.not_valid_before,
            "Not Valid After" : cert.not_valid_after,
            "Public Key Algorithm" : cert.public_key.algorithm.upper(),
            "SHA-1": cert.sha1_fingerprint,
            "CA" : cert.ca,
            "Max Path Length" : cert.max_path_length
            }
        dict_chain.append(dict_cert)
    return dict_chain

microsft_edge, google_chrome, mozilla_firefox = get_trust_stores()

def security_level(dict_chain, trust_store):
    """
    Funcion que valida que el sha1 raiz de la cadena de certificados este en el trust store (trust_store es un arreglo de diccionarios)
    Funcion que valida si la fecha de expiracion del certificado raiz es mayor a la fecha actual: 
    por ejemplo si el certificado raiz expira el 2021-01-01 y la fecha actual es 2019-12-31 entonces el certificado no es valido
    """
    security_level = 0
    is_sha1_in_trust_store = False
    is_valid_date = False

    if dict_chain == []:
        security_level = 1
        return security_level

    size_chain = len(dict_chain)
    for cert in trust_store:
        sha1 = ":".join(dict_chain[0]["SHA-1"][i:i+2] for i in range(0, len(dict_chain[0]["SHA-1"]), 3))
        if sha1 == cert["SHA-1"]:
            is_sha1_in_trust_store = True
            validity_str = cert ["validity"] 
            validity = validity_str.split(" - ")
            if (dict_chain[0]["Not Valid After"].strftime("%Y-%m-%d")  ) >= (validity[0]):
                is_valid_date = True

    if (is_sha1_in_trust_store == True and is_valid_date == True):
        security_level = 3

    # si el sha1 del certificado raiz esta en el trust store pero la fecha de expiracion es menor a la fecha actual entonces el nivel de seguridad es 2
    if (is_sha1_in_trust_store == True and is_valid_date == False):
        security_level = 2

    # Si el certificado raiz es autofirmado entonces el nivel de seguridad es 1
    if (dict_chain[0]["Subject"] == dict_chain[size_chain-1]["Isuuer"]):
        security_level = 1

    # Si el certificado raiz no esta en el trust store entonces el nivel de seguridad es 1
    if (is_sha1_in_trust_store == False):
        security_level = 1

    # Si el certificado raiz es autofirmado y el sha1 del certificado raiz esta en el trust store entonces el nivel de seguridad es 2
    if (dict_chain[0]["Subject"] == dict_chain[size_chain-1]["Isuuer"] and is_sha1_in_trust_store == True):
        security_level = 2

    return security_level


def view_security_level(url):
    """
    Funcion que retorna el nivel de seguridad de un sitio web a partir de su URL en formato https://www.ejemplo.com
    """
    is_valid, response = is_valid_URL(url)
    if is_valid == True:
        chain = get_certificate_chain(url)
        dict_chain = generate_dict_chain(chain)
        Mozila = security_level(dict_chain, mozilla_firefox)
        Chrome = security_level(dict_chain, google_chrome)
        Edge = security_level(dict_chain, microsft_edge)
        return Mozila, Chrome, Edge
    else:
        return 0, 0, 0

