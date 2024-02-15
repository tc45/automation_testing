import api_calls
import pandas as pd
from openpyxl import Workbook
from netmiko import ConnectHandler
from threading import Thread
from jinja2 import Environment, FileSystemLoader
import ipaddress
import requests


def fetch_request_data(url, api_token):
    """
    Fetch data from a given URL with an API token for authorization.

    :param url: The URL to make the request to.
    :param api_token: The API token used for authorization.
    :return: A Python dict containing the JSON response or an error message.
    """
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {api_token}",
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()  # Returns the JSON response as a Python dict
    else:
        return f"Failed to retrieve data, status code: {response.status_code}"


def get_csv_data(filename):
    """
    Read CSV data into a dictionary of records.

    :param filename: The name of the CSV file to read.
    :return: A list of dictionaries representing the rows of the CSV.
    """
    df = pd.read_csv(filename)
    if not df.empty:
        device_data_dict = df.to_dict(orient='records')
    else:
        device_data_dict = {}
    return device_data_dict


def create_device_report(filename, devices):
    """
    Create an Excel report for a list of devices.

    :param filename: The name of the Excel file to create.
    :param devices: A list of tuples containing device information.
    """
    wb = Workbook()
    ws = wb.active
    ws.append(["Device Name", "IP Address", "Location"])
    for device in devices:
        ws.append(device)
    wb.save(filename)


def read_device_info(filename):
    """
    Read device information from a CSV file using Pandas.

    :param filename: The name of the CSV file to read.
    :return: A DataFrame containing the device information.
    """
    return pd.read_csv(filename)


def execute_commands_on_devices_threading(filename):
    """
    Execute commands on devices listed in a CSV file using threading.

    :param filename: The name of the CSV file containing device and command information.
    :return: A list of results with command outputs for each device.
    """
    device_info_df = read_device_info(filename)
    threads = []
    results = []

    # Create a thread for each device and start it
    for index, row in device_info_df.iterrows():
        device_info = row.to_dict()
        thread = Thread(target=connect_and_execute_thread, args=(device_info, results))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    return results


def connect_and_execute_thread(device_info, results):
    """
    Connect to a device and execute a command in a separate thread.

    :param device_info: A dictionary containing device connection details.
    :param results: A shared list to store the results.
    """
    device = {
        'device_type': device_info['device_type'],
        'host': device_info['host'],
        'username': device_info['username'],
        'password': device_info['password'],
        'use_keys': False,
        'allow_agent': False
    }
    command = device_info['command']
    try:
        net_connect = ConnectHandler(**device)
        output = net_connect.send_command(command)
        net_connect.disconnect()
        results.append((device_info['host'], command, output))
    except Exception as e:
        print(f"Failed to connect to {device_info['host']}: {e}")
        results.append((device_info['host'], command, f"Connection failed: {e}"))


def write_results_to_excel(results, output_filename):
    """
    Write command execution results to an Excel file.

    :param results: A list of tuples containing the results.
    :param output_filename: The name of the Excel file to create.
    """
    wb = Workbook()
    ws = wb.active
    ws.append(["Host", "Command", "Output"])
    for result in results:
        ws.append(result)
    wb.save(output_filename)


def render_templates_for_devices(template_path, template_name, devices_df):
    """
    Render configuration templates for devices using Jinja2.

    :param template_path: The path to the directory containing the template file.
    :param template_name: The name of the template file.
    :param devices_df: A DataFrame containing device information.
    :return: A list of tuples with hostnames and rendered configurations.
    """
    env = Environment(loader=FileSystemLoader(template_path))
    template = env.get_template(template_name)
    configs = []

    for index, device in devices_df.iterrows():
        config = template.render(device.to_dict())
        configs.append((device['host'], config))

    return configs


def apply_configurations_from_csv(csv_filename, template_path, template_name):
    """
    Apply configurations to devices based on a CSV file and a Jinja2 template.

    :param csv_filename: The filename of the CSV containing device details.
    :param template_path: The path to the Jinja2 templates directory.
    :param template_name: The name of the Jinja2 template file.
    """
    devices_df = read_device_info(csv_filename)
    # Apply the invert_subnet_mask function to the 'subnet_mask' column
    if 'subnet_mask' in devices_df.columns:
        devices_df['host_mask'] = devices_df['subnet_mask'].apply(invert_subnet_mask)

    device_configs = render_templates_for_devices(template_path, template_name, devices_df)

    for host, config in device_configs:
        device_details = devices_df.loc[devices_df['host'] == host].iloc[0].to_dict()
        device_connection_details = {
            'device_type': device_details['device_type'],
            'host': device_details['host'],
            'username': device_details['username'],
            'password': device_details['password']
            # Add any additional Netmiko ConnectHandler arguments here
        }
        apply_configuration(device_connection_details, config)


def apply_configuration(device_details, configuration):
    """
    Apply a given configuration to a device using Netmiko.

    :param device_details: A dictionary containing the device's connection details.
    :param configuration: The configuration commands to be applied to the device.
    """
    try:
        with ConnectHandler(**device_details) as net_connect:
            output = net_connect.send_config_set(configuration.split('\n'))
            print(f"Configuration applied to {device_details['host']}: {output}")
    except Exception as e:
        print(f"Failed to apply configuration to {device_details['host']}: {e}")


# Function to invert subnet mask
def invert_subnet_mask(subnet_mask):
    """
    Invert a subnet mask to calculate the wildcard mask.

    :param subnet_mask: The subnet mask to be inverted.
    :return: The inverted subnet mask as a string.
    """
    # Create an IPv4 network object from the subnet mask
    net = ipaddress.IPv4Network('0.0.0.0/' + subnet_mask, strict=False)
    # Invert the netmask and return it as a string
    inverted_mask = str(net.hostmask)
    return inverted_mask


def get_device_facts(device_type, hostname, username, password):
    """
    Retrieve facts about a device using a network driver.

    :param device_type: The type of device (e.g., 'ios', 'junos').
    :param hostname: The hostname or IP address of the device.
    :param username: The username for device authentication.
    :param password: The password for device authentication.
    :return: A dictionary containing device facts.
    """
    driver = get_network_driver(device_type)
    with driver(hostname, username, password, optional_args={'secret': 'your_enable_password'}) as device:
        return device.get_facts()


def add_one_to_network(network_address):
    """
    Add one to the network address to calculate the first host address.

    :param network_address: The network address in CIDR notation.
    :return: The first host address in the network as a string.
    """
    network = ipaddress.IPv4Interface(network_address)
    first_host = str(network.network.network_address + 1)
    return first_host


def main():

    # Example usage for simple requests
    print("* " * 10 + "Starting basic requests function." + "* " * 10)
    url = "https://httpbin.org/get"
    api_token = "12345678"
    devices_data = fetch_request_data(url, api_token)
    print(devices_data)

    # Example usage for parsing CSVs using Pandas
    print("* " * 10 + "Starting Pandas CSV function." + "* " * 10)
    filename = 'devices.csv'
    device_info = get_csv_data(filename)
    print(device_info)

    # Import CSV to pandas, multi-thread connections to each device, collect data, write to Excel.
    print("* " * 10 + "Starting multi threading function." + "* " * 10)
    input_filename = 'device_commands.csv'
    output_filename = 'command_outputs.xlsx'
    results = execute_commands_on_devices_threading(input_filename)
    write_results_to_excel(results, output_filename)
    print("Done writing command outputs to Excel.")

    # Use Jinja2 template to apply loopback configuration and enable in OSPF Area 0
    print("* " * 10 + "Starting Jinja2 function." + "* " * 10)
    csv_filename = 'devices.csv'
    template_path = './templates'
    template_name = 'config.j2'
    apply_configurations_from_csv(csv_filename, template_path, template_name)
    print(config)


if __name__ == "__main__":
    main()

