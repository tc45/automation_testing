import requests
from requests.auth import HTTPDigestAuth


def test_get_with_basic_auth():
    """
    Sends a GET request to a URL that requires basic authentication.

    The function attempts to authenticate using a predefined username and password,
    prints the response JSON if successful, or an error message otherwise.
    """
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
    """
    Sends a POST request with basic authentication and some data.

    The function sends data to the server using a POST request with basic authentication,
    prints the response JSON if successful, or an error message otherwise.
    """
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
    """
    Sends a GET request with bearer token authentication.

    The function sends a GET request with an Authorization header containing a bearer token,
    prints the response JSON if successful, or an error message otherwise.
    """
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
    """
    Sends a POST request with bearer token authentication and data.

    The function sends a POST request with an Authorization header containing a bearer token,
    along with some data, prints the response JSON if successful, or an error message otherwise.
    """
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
    """
    Sends a GET request with digest authentication.

    The function attempts to authenticate using digest authentication against a test endpoint,
    prints the response JSON if successful, or an error message otherwise.
    """
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
    """
    Sends a POST request with digest authentication and data.

    The function sends a POST request with digest authentication,
    along with some data, prints the response JSON if successful, or an error message otherwise.
    """
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
    """
    Main function to execute test functions for different authentication methods.
    """
    test_get_with_basic_auth()
    test_post_with_basic_auth()
    test_get_with_bearer_token()
    test_post_with_bearer_token()
    test_get_with_digest_auth()
    test_post_with_digest_auth()


if __name__ == "__main__":
    main()
