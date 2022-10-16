from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib import messages

from .forms import urlForm
from .src.verify import get_results, is_valid_URL, get_file_valid_urls, get_trust_stores

lista_urls = []
lista_colors = []
lista_browsers = ['Microsoft Edge', 'Google Chrome', 'Mozilla Firefox']
display_button = True
display_warning = False
display_error = False
display_success = False
message_response = ""

microsoft_store, google_store, mozilla_store = get_trust_stores()

def index(request):
  global lista_colors
  global lista_urls
  global display_warning
  global display_error
  global display_success
  global message_response
  display_button = True
  if request.method == 'POST':
    form = urlForm(request.POST)
    if form.is_valid():

      # Obteniendo URL como string
      url_string = form.cleaned_data['url']

      # validación de URL
      valid_url, response = is_valid_URL(url_string)

      # si es válida y existe la URL
      if valid_url == True:
        lista_urls.insert(0, url_string)

         # Funcion que verifica el nivel de confianza
        lista_browsers_colors = get_results(url_string)
        lista_colors.insert(0, lista_browsers_colors)

        # para mostrar el nivel de confianza con colores
        results = zip(lista_urls, lista_colors)
        context = {'form': form,
                    'lista_browsers':lista_browsers,
                    'results':results,
                    'display': display_button}
      # si no es válida y no existe la URL
      else:
        # Para mostrar mensajes de error
        messages.add_message(request, messages.ERROR, response)

        # si la lista de URLs esta vacia
        if len(lista_urls) == 0:
          display_button = False
          context = {'form': form,
                      'display': display_button}
        # si la lista de URLs no esta vacia
        else:
          results = zip(lista_urls, lista_colors)
          context = {'form': form,
                      'lista_browsers':lista_browsers,
                      'results':results,
                      'display': display_button}
      return render(request, 'form.html', context)

  elif request.method == 'GET':
    # mensajes de error, warning o éxito en el procesamiento del archivo
    if display_warning == True:
      messages.add_message(request, messages.WARNING, message_response)
      display_warning = False
    elif display_error == True:
      messages.add_message(request, messages.ERROR, message_response)
      display_error = False
    elif display_success == True:
      messages.add_message(request, messages.SUCCESS, message_response)
      display_success = False

    form = urlForm()
    results = zip(lista_urls, lista_colors)

    # si la lista de URLs esta vacía
    if len(lista_urls) == 0:
      display_button = False
      context = {'form': form, 'display': display_button}
    # si la lista de URLs NO esta vacía
    else:
      display_button = True
      context = {'form': form,
                'lista_browsers':lista_browsers,
                'results':results,
                'display': display_button}
    return render(request, 'form.html', context)

def upload_file(request):
  global lista_colors
  global lista_urls
  global display_button
  global display_warning
  global display_error
  global display_success
  global message_response
  if request.method == 'POST':

    # leemos el archivo y lo obtenemos en bytes
    file_urls = request.FILES['file'].readlines()

    # decodificamoes y limpiamos la data
    file_urls = [ url.decode("utf-8").replace('\n','') for url in file_urls ]

    # obtenemos las urls válidas del archivo y sus colores respectivos
    urls, colors = get_file_valid_urls(file_urls)

    # agregamos a las listas resultantes
    lista_urls = urls + lista_urls
    lista_colors = colors + lista_colors

    # verificamos si todas las URLs del archivo han sido procesadas
    # caso contrario mostramos mensajes de error al usuario
    if len(urls) > 0:
      display_button = True
      if len(file_urls) != len(urls) :
        display_warning = True
        message_response = "Existen URLs no válidas que no han sido procesadas"
      else:
        display_success = True
        message_response = "Todas las URLs han sido procesadas exitosamente"
    else:
      display_error = True
      message_response = "Todas las URLs son inválidas"

  return redirect('index')

def clean(request):
  global lista_colors
  global lista_urls
  lista_urls = []
  lista_colors = []
  return redirect('index')

def google_trust_Store(request):
  return render(request, "google_trust_store/google_trust_store.html", {'certificates': google_store})

def microsoft_trust_Store(request):
  return render(request, "microsoft_trust_store/microsoft_trust_store.html", {'certificates': microsoft_store})

def mozilla_trust_Store(request):
  return render(request, "mozilla_trust_store/mozilla_trust_store.html", {'certificates': mozilla_store})