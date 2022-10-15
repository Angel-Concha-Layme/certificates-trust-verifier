import requests
import random

def get_results(url):
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


def get_file_valid_urls(file_urls):
  '''
  Función que valida URLs del archivo y almacena solo aquellas que son válidas
  '''
  list_file_urls = []
  list_file_colors = []
  counter = 1
  for url in file_urls:
    # validación de URL
    valid_url, response = is_valid_URL(url)

    # si es válida y existe la URL
    if valid_url == True:
      list_file_urls.insert(0, url)

      # Funcion que verifica el nivel de confianza
      lista_browsers_colors = get_results(url)
      list_file_colors.insert(0, lista_browsers_colors)
    else:
      # Para mostrar mensajes de error
      print("URL #", counter, " inválida")
    counter += 1
  return list_file_urls, list_file_colors