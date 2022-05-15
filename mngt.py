from pprint import pprint

import constants

def main():
  import json, requests
  from requests.exceptions import RequestException, HTTPError, URLRequired

  # Configuration Values
  domain = constants.AUTH0_DOMAIN

  # Get an Access Token from Auth0
  base_url = f"https://{domain}"

  # Add the token to the Authorization header of the request
  headers = {
    'Authorization': f'Bearer {constants.AUTH0_MNGT_TOKEN}',
    'Content-Type': 'application/json'
  }

  # Get all Applications using the token
  try:
    res = requests.get(f'{base_url}/api/v2/users', headers=headers)
    pprint(res.json())
  except HTTPError as e:
    print(f'HTTPError: {str(e.code)} {str(e.reason)}')
  except URLRequired as e:
    print(f'URLRequired: {str(e.reason)}')
  except RequestException as e:
    print(f'RequestException: {e}')
  except Exception as e:
    print(f'Generic Exception: {e}')

# Standard boilerplate to call the main() function.
if __name__ == '__main__':
  main()
