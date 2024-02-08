import requests
from requests.auth import HTTPDigestAuth


# This is a test

def test_get_with_basic_auth():
    url = 'https://httpbin.org/basic-auth/user/password'
    auth = requests.auth.HTTPBasicAuth('user', 'password')
    response = requests.get(url, auth=auth)
    if response.status_code == 200:
        print("Success:", response.json())
    elif response.status_code == 401:
        print("Authentication error")
    else:
        print(f"Error {response.status_code}: {response.text}")


def test_post_with_basic_auth():
    url = 'https://httpbin.org/post'
    auth = requests.auth.HTTPBasicAuth('user', 'password')
    data = {'key': 'This is the datapoint'}
    response = requests.post(url, data=data, auth=auth)
    if response.status_code == 200:
        print("Success:", response.json())
    elif response.status_code == 401:
        print("Authentication error")
    else:
        print(f"Error {response.status_code}: {response.text}")


def test_get_with_bearer_token():
    url = 'https://httpbin.org/get'
    headers = {'Authorization': 'Bearer YOUR_TOKEN_HERE'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        print("Success:", response.json())
    elif response.status_code == 401:
        print("Authentication error")
    else:
        print(f"Error {response.status_code}: {response.text}")


def test_post_with_bearer_token():
    url = 'https://httpbin.org/post'
    headers = {'Authorization': 'Bearer YOUR_TOKEN_HERE'}
    data = {'key': 'This is test Bearer data.'}
    response = requests.post(url, data=data, headers=headers)
    if response.status_code == 200:
        print("Success:", response.json())
    elif response.status_code == 401:
        print("Authentication error")
    else:
        print(f"Error {response.status_code}: {response.text}")


def test_get_with_digest_auth():
    url = 'https://httpbin.org/digest-auth/auth/user/password'
    auth = HTTPDigestAuth('user', 'password')
    response = requests.get(url, auth=auth)
    if response.status_code == 200:
        print("Success:", response.json())
    elif response.status_code == 401:
        print("Authentication error")
    else:
        print(f"Error {response.status_code}: {response.text}")


def test_post_with_digest_auth():
    url = 'https://httpbin.org/post'
    auth = HTTPDigestAuth('user', 'password')
    data = {'key': 'This is the data for digest_auth POST'}
    response = requests.post(url, data=data, auth=auth)
    if response.status_code == 200:
        print("Success:", response.json())
    elif response.status_code == 401:
        print("Authentication error")
    else:
        print(f"Error {response.status_code}: {response.text}")


def main():
    test_get_with_basic_auth()
    test_post_with_basic_auth()
    test_get_with_bearer_token()
    test_post_with_bearer_token()
    test_get_with_digest_auth()
    test_post_with_digest_auth()


if __name__ == "__main__":
    main()
