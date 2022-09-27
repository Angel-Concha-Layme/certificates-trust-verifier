from django import forms

class urlForm(forms.Form):
  url = forms.CharField(label="", max_length=600, widget=forms.TextInput(attrs={'id': 'inputURL','size':'60', 'placeholder': ' ' * 40 +'[ ingresar URL a verificar ...]'}))