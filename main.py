

import os
from netmiko_tests import ConnectHandler

print(os.environ)
var = "string"
ip_list = ["10.1.1.1", "10.2.2.2", "10.3.3.3"]
for ip in ip_list:
    print(ip)
    print(var)
try:
    conn = ConnectHandler(
        device_type='cisco_ios',
        host='10.1.1.1',
        username='admin',
        password='cisco',
    )
except Exception as e:
    print(f"Unable to connect to the device. {e}")

print(os.environ["ALLUSERSPROFILE"])


def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print_hi('PyCharm')

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
