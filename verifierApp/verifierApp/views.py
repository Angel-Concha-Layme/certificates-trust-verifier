from django.http import HttpResponse
from django.shortcuts import render
from django.contrib import messages

from .forms import urlForm
from .src.verify import get_results

lista_urls = []
lista_colors = []
lista_browsers = ['Microsoft Edge', 'Google Chrome', 'Mozilla Firefox']

def index(request):
  global lista_colors
  global lista_urls
  display = True
  if request.method == 'POST':
    form = urlForm(request.POST)
    if form.is_valid():
      url_string = form.cleaned_data['url']
      lista_urls.insert(0, url_string)

      lista_browsers_colors = get_results(url_string) # aqui va funcion que verifica los certificados
      lista_colors.insert(0, lista_browsers_colors)

      results = zip(lista_urls, lista_colors)
      context = {'form': form,
                  'lista_browsers':lista_browsers,
                  'results':results,
                  'display': display}
      return render(request, 'form.html', context)
  else:
    lista_urls = []
    lista_colors = []
    display = False
    form = urlForm()
  return render(request, 'form.html', {'form': form, 'display': display})
