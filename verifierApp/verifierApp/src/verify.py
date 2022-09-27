import random

def get_results(url):
  print(url)
  result = [random.sample(['red', 'white' ,'white', 'white'],4),
            random.sample(['white', 'white' ,'green', 'white'],4),
            random.sample(['white', 'green' ,'white', 'white'],4)]
  return result