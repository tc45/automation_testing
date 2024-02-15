from netmiko import ConnectHandler, file_transfer
from netmiko.base_connection import BaseConnection
from threading import Thread
import time
from netaddr import IPAddress, IPNetwork
import sys
from tabulate import tabulate
import argparse
import inspect

# Example usage for simple connectivity
# This is not a best practice to hard code values into the script.  Used for example purposes only.
cisco_device = {
    'device_type': 'cisco_ios',
    'host': '192.168.1.233',
    'username': 'cisco',
    'password': 'cisco123',
}
cisco_device2 = {
    'device_type': 'cisco_ios',
    'host': '192.168.1.232',
    'username': 'cisco',
    'password': 'cisco123',
}
nxos_device = {
    'device_type': 'cisco_nxos',
    'host': '192.168.1.250',
    'username': 'admin',
    'password': '@dmin123',
}

cisco_devices = [cisco_device, cisco_device2]
nxos_devices = [nxos_device]


def connect_to_device(device):
    """
    Establishes a connection to the specified network device.

    Parameters:
    - device: A dictionary containing the device connection parameters.  Required fields in dictionary are:
        - device_type: The type of device to connect to (cisco_ios, cisco_xr, etc.)
        - host: The IP address or hostname of the device
        - username: The username to use for the connection
        - password: The password to use for the connection

    Returns:
    - The connection object if successful, or prints an error message and returns None if not.
    """
    try:
        connection = ConnectHandler(**device)
        print(f"Successfully connected to {device['host']}")
        return connection
    except Exception as e:
        print(f"Failed to connect to {device['host']}: {e}")


def execute_command(connection, command):
    """
    Executes a single command on a connected network device.

    Parameters:
    - connection: The Netmiko connection object to the device.
    - command: The command string to be executed on the device.

    Returns:
    - The output of the command as a string, or prints an error message if the command fails.
    """
    try:
        output = connection.send_command(command)
        return output
    except Exception as e:
        print(f"Failed to execute command: {e}")


def make_configuration_change(connection, commands):
    """
    Applies a list of configuration commands to a network device.

    Parameters:
    - connection: The Netmiko connection object to the device.
    - commands: A list of strings representing the configuration commands to be applied.

    Returns:
    - The output of the configuration change, or "Failed to connect" if an exception occurs.
    """
    try:
        connection.enable()  # Ensure in enable mode
        output = connection.send_config_set(commands)
        return output
    except Exception as e:
        print(f"Failed to make configuration change: {e}")
        return "Failed to connect"


def transfer_file(connection, source_file, dest_file, file_action='put'):
    """
    Transfers a file to or from a network device.

    Parameters:
    - connection: The Netmiko connection object to the device.
    - source_file: The path to the source file.
    - dest_file: The destination file path on the device.
    - file_action: The transfer action to perform ('put' for upload, 'get' for download).

    Prints the result of the file transfer and any errors encountered.
    """
    try:
        transfer_dict = file_transfer(connection,
                                      source_file=source_file,
                                      dest_file=dest_file,
                                      file_system='unix:',
                                      direction=file_action,
                                      overwrite_file=True)
        print(f"File Transfer Result: {transfer_dict}")
        if transfer_dict['file_exists']:
            print(f"File {dest_file} already exists on the device.")
    except Exception as e:
        print(f"Failed to transfer file: {e}")


def enable_session_logging(connection, log_file="session_log.txt"):
    """
    Enables session logging for a network device connection.

    Parameters:
    - connection: The Netmiko connection object to the device.
    - log_file: The name of the file where the session log will be saved.

    Prints a message indicating that session logging is enabled.
    """
    connection.session_log = open(log_file, "w")  # Open the log file in write mode
    print(f"Session logging enabled, output will be saved to {log_file}")


def connect_and_execute(device_dictionary, command):
    """
    Connects to a network device and executes a single command.

    Parameters:
    - device_dictionary: A dictionary with the device connection parameters.
    - command: The command string to be executed on the device.

    Prints the output of the command or an error message if the connection or execution fails.
    """
    try:
        with ConnectHandler(**device_dictionary) as conn:
            output = conn.send_command(command)
            print(f"Output from {device_dictionary['host']}:\n{output}")
    except Exception as e:
        print(f"Failed on {device_dictionary['host']}: {e}")


def device_worker(device, command):
    """
    Worker function to connect to a device and execute a command, designed to be used with threading.

    Parameters:
    - device: A dictionary with the device connection parameters.
    - command: The command string to be executed on the device.

    Prints the output of the command or an error message if the connection or execution fails.
    """
    try:
        with ConnectHandler(**device) as conn:
            output = conn.send_command(command)
            print(f"--- Output from {device['host']} ---\n{output}\n")
    except Exception as e:
        print(f"Failed to connect or execute on {device['host']}: {e}")


def execute_concurrently(devices, command):
    """
    Executes a command concurrently on multiple devices using threading.

    Parameters:
    - devices: A list of dictionaries, each containing connection parameters for a device.
    - command: The command string to be executed on each device.

    Waits for all threads to complete before returning.
    """
    threads = []
    for device in devices:
        thread = Thread(target=device_worker, args=(device, command))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()


# def execute_interactive_command(connection, command, expect_string, response):
#     """
#     Executes an interactive command on a network device.
#
#     Parameters:
#     - connection: The Netmiko connection object to the device.
#     - command: The command to be executed on the device.
#     - expect_string: The string to expect before sending the response. This indicates the command is waiting for user input.
#     - response: The response to send when the expect_string is detected.
#
#     Returns:
#     - The output of the command execution.
#     """
#     # Sending the command and waiting for the expected prompt
#     output = connection.send_command_timing(command)
#     if expect_string in output:
#         # The expected prompt was detected, send the response
#         output += connection.send_command_timing(response)
#     else:
#         # If the prompt didn't appear as expected, handle accordingly
#         print(f"Expected prompt '{expect_string}' not found in the output.")
#     return output


def verify_command_output(connection, command, success_keywords, error_keywords):
    """
    Verifies the output of a command executed on a network device against success and error keywords.

    Parameters:
    - connection: The Netmiko connection object to the device.
    - command: The command string to be executed on the device.
    - success_keywords: A list of keywords indicating successful command execution.
    - error_keywords: A list of keywords indicating an error in command execution.

    Prints messages indicating whether success or error keywords were found in the command output.
    """
    output = connection.send_command(command)
    if any(keyword in output for keyword in success_keywords):
        print("Success detected in command output.")
    elif any(keyword in output for keyword in error_keywords):
        print(command)
        print(f"{output}\nError detected in command output.")
    else:
        print("Command output does not contain known success or error indicators.")


class CustomDevice(BaseConnection):
    def session_preparation(self):
        """
        Prepare the session after the connection has been established.

        This method overrides the BaseConnection's session_preparation to handle
        custom prompts.
        """
        # Set terminal length and width
        self.set_terminal_width(command="terminal width 511")
        self.disable_paging(command="terminal length 0")

        # Setting base prompt for different modes
        self.find_prompt(delay_factor=1)

        # Check if we're in user mode and elevate if necessary. This is just an example and
        # might need adjustment based on the actual device behavior.
        if self.find_prompt().endswith('>'):
            self.enable()  # Normally to get into privileged mode. Adjust if your device uses a different command.

        # After enable, ensure we're not in config mode. If in config mode, exit to privileged mode.
        if self.find_prompt().endswith('$(config)#'):
            self.exit_config_mode()

        # Now should be in privileged mode, set base prompt
        self.set_base_prompt()

    def config_mode(self, config_command='configure terminal', pattern=''):
        # Enter into configuration mode on remote device.
        return super().config_mode(config_command=config_command, pattern=r'\$\{config\}#')

    def exit_config_mode(self, exit_config='exit', pattern=''):
        # Exit from configuration mode.
        return super().exit_config_mode(exit_config=exit_config, pattern=pattern)

    def check_config_mode(self, check_string='$(config)#', pattern=''):
        # Checks if the device is in configuration mode or not.
        return super().check_config_mode(check_string=check_string, pattern=pattern)


def show_interface_to_netmask(device_params):
    """
    Retrieves the IP interface brief and converts the IP addresses to CIDR notation.

    Parameters:
    - device_params: A dictionary containing the device connection parameters.

    Returns:
    - The raw output of the 'show interface' command after processing.
    """
    # Create a connection object
    try:
        with ConnectHandler(**device_params) as net_connect:
            # Send command to device
            output = net_connect.send_command('show interface', use_textfsm=True)
            if net_connect:
                net_connect.disconnect()
                # Process each entry in the output
                for entry in output:
                    interface = entry['interface']
                    ip_address = entry['ip_address']
                    cidr = entry['prefix_length']

                    # Skip entries without an IP address
                    if not cidr:
                        continue

                    # Calculate CIDR notation
                    netmask = str(IPNetwork(f"{ip_address}/{cidr}").netmask)

                    # Output interface and IP in CIDR notation
                    print(f"{interface}: {ip_address} {netmask}")
    except Exception as e:
        print(f"Failed to connect to {device_params['host']}: {e}")
        return output


def simple_connectivity_example():
    print("* " * 15 + "Simple Connectivity Example" + " * " * 15)
    connection = connect_to_device(cisco_device)
    if connection:
        print("Connected successfully!  Disconnecting...")
        connection.disconnect()


def single_command_execution():
    print("* " * 15 + "Simple command execution Example" + " * " * 15)
    devices = [cisco_device, cisco_device2]
    start_time = time.time()
    for device in devices:
        connection = connect_to_device(cisco_device)
        if connection:
            command_output = execute_command(connection, 'show ip interface brief')
            connection.disconnect()
            print(f"Command output:\n{command_output}")
    end_time = time.time()
    duration = end_time - start_time
    print(f"Execution time: {duration:.2f} seconds")


def execute_interactive_command(connection, command):
    """
    Execute an interactive command on a device through the given connection,
    handling both 'Save?' and 'reload?' prompts.

    Parameters
    ----------
    connection : Connection
        The connection object to the device.
    command : str
        The command to execute on the device.

    Returns
    -------
    output : str
        The output from the device after executing the command.
    """
    timeout = 3    # Timeout in seconds
    # # Send the 'reload' command to the device
    # connection.send_command("write mem")
    output = connection.send_command_timing(command)

    # If the first prompt was 'Save?', wait for the 'reload?' prompt next
    if "Save?" in output:
        output += connection.send_command_timing('y', delay_factor=timeout)
        print("Config saved.")

    if "confirm" in output:
        output += connection.send_command_timing('y', delay_factor=timeout)
        print("Reload confirmed.  Please wait 2-5 minutes for device to come back online.")

    return output


def get_arguments(parser):
    # Use reflection to find all functions in the current module that end with "_example"
    current_module = globals()
    for function_name, function_obj in current_module.items():
        if callable(function_obj) and function_name.endswith('_example'):
            # Add each function as an argument
            parser.add_argument(f'--{function_name}', action='store_true',
                                help=f'Run {function_name} function')

    # Parse the arguments
    args = parser.parse_args()

    return args


def text_fsm_example():
    devices = [cisco_device, cisco_device2]
    print("* " * 15 + "text_fsm command execution Example" + " * " * 15)
    for device in devices:
        command_output = show_interface_to_netmask(device)
        print(f"Command output:\n{command_output}")


def config_change_example():
    # Example usage for configuration changes
    print("* " * 15 + "Multiple command execution Example" + " * " * 15)
    commands = [
        'interface loopback 101',
        'ip address 10.1.1.1 255.255.255.255',
        'description Netmiko Test Interface',
        'no shutdown',
    ]
    connection = connect_to_device(cisco_device)
    if connection:
        command_output = make_configuration_change(connection, commands)
        connection.disconnect()
        print(f"Command output:\n{command_output}")


def transfer_file_to_device_example():
    # Example usage for transferring files
    print("* " * 15 + "Transfer File Example" + " * " * 15)
    source_file = 'test.txt'
    dest_file = 'test.txt'
    connection = connect_to_device(cisco_device)
    if connection:
        transfer_file(connection, source_file, dest_file, file_action='put')
        connection.disconnect()


def session_logging_example():
    # Example usage for session logging
    print("* " * 15 + "Session Logging Example" + " * " * 15)
    cisco_device['session_log'] = 'session_log.txt'
    connection = connect_to_device(cisco_device)

    if connection:
        # enable_session_logging(connection)
        # Execute some commands to log
        connection.send_command("show version")
        connection.send_command("show ip interface br")
        connection.send_command("show run")
        connection.session_log.close()
        connection.disconnect()


def multi_vendor_example():
    # Multi-vendor support example.
    print("* " * 15 + "Multiple vendor execution Example" + " * " * 15)
    # Example usage for a Cisco IOS device
    connect_and_execute(cisco_device, 'show ip int brief')
    # Example usage for a NXOS device.  Grab default VRF as well as management VRF
    connect_and_execute(nxos_device, 'show ip int brief vrf default')
    connect_and_execute(nxos_device, 'show ip int brief vrf management')


def multi_thread_example():
    # Example usage - MultiThreading

    execute_concurrently(cisco_devices, "show run")


def interactive_prompt_example():
    print("* " * 15 + "Interactive commands execution Example" + " * " * 15)
    conn = connect_to_device(cisco_device)
    if conn:
        config_register_commands = [
            'config t',
            'config-register 0x2102',
        ]
        output = conn.send_config_set(config_register_commands)
        reload_command = 'reload'
        # Execute 'reload' command and handle prompts
        output = execute_interactive_command(conn, reload_command)
        print(f"Reload command execution result:\n{output}")

        conn.disconnect()


def print_execution_times(function_runs):
    # Convert the list of dictionaries to a list of lists for tabulate
    table_data = [[details["function_name"], details["execution_time"]] for details in function_runs]

    # Define headers for the table
    headers = ["Function Name", "Execution Time"]

    # Create the table
    table = tabulate(table_data, headers=headers, tablefmt="grid")
    print(table)


def main():
    # Create arg parser
    parser = argparse.ArgumentParser(
        description="Netmiko test examples contains multiple examples for basic usage of the "
                    "Netmiko library.  To run all examples in the file simply run the script with no arguments.  "
                    "To run a specific example use the --function_name flag with the function name you want to run."
    )
    args = get_arguments(parser)

    runtimes = []

    # Find all functions ending with '_example' and create a dictionary
    functions = {name: obj for name, obj in globals().items()
                 if callable(obj) and name.endswith('_example')}

    # Check which functions were selected by the user
    selected_functions = [name for name, selected in vars(args).items() if selected]

    if not selected_functions:
        # No specific function selected, run all functions
        for function_name, function in functions.items():
            start_time = time.time()
            function()
            end_time = time.time()
            duration = end_time - start_time
            function_run_details = {
                "function_name": function_name,
                "execution_time": duration
            }
            runtimes.append(function_run_details)
    else:
        # Run only the selected functions
        for function_name in selected_functions:
            if function_name in functions:
                start_time = time.time()
                functions[function_name]()  # Call the function
                end_time = time.time()
                duration = end_time - start_time
                function_run_details = {
                    "function_name": function_name,
                    "execution_time": duration
                }
                runtimes.append(function_run_details)
            else:
                print(f"Unknown function: {function_name}")

    print_execution_times(runtimes)

    # # Find all functions ending with '_example' and create a dictionary
    # functions = {name: obj for name, obj in globals().items()
    #              if callable(obj) and name.endswith('_example')}
    #
    # # Check for at least one argument (the script name)
    # if len(sys.argv) == 1:
    #     # No function specified, run all functions without arguments
    #     for function in functions.values():
    #         start_time = time.time()
    #         function()
    #         end_time = time.time()
    #         duration = end_time - start_time
    #         function_run_details = {
    #             "function_name": function.__name__,
    #             "execution_time": duration
    #         }
    #         runtimes.append(function_run_details)
    # else:
    #     function_name = sys.argv[1]
    #     args = sys.argv[2:]  # Additional arguments for the function
    #     if function_name in functions:
    #         start_time = time.time()
    #         functions[function_name](*args)  # Call the function with any additional arguments
    #         end_time = time.time()
    #         duration = end_time - start_time
    #         function_run_details = {
    #             "function_name": function.__name__,
    #             "execution_time": duration
    #         }
    #         runtimes.append(function_run_details)
    #     else:
    #         print(f"Unknown function: {function_name}")
    # print_execution_times(runtimes)


if __name__ == "__main__":

    main()





    # # Example usage for interactive commands
    # connection = connect_to_device(cisco_device)
    # if connection:
    #     execute_interactive_command(connection, 'delete unix:test.txt', 'Confirm', 'y')
    #     connection.disconnect()
    #
    #
    # # Example usage for error and keyword detection
    # success_keywords = ['completed', 'success']
    # error_keywords = ['failed', 'error', 'Invalid']
    # connection = connect_to_device(cisco_device)
    # if connection:
    #     verify_command_output(connection, "interface gig 101", success_keywords, error_keywords)
    #     connection.disconnect()
    #
    # # # Register the custom device type
    # # ConnectHandler.register_device_type('custom_device', CustomDevice)
    #
    # # # Use the custom device
    # # custom_device = {
    # #     'device_type': 'custom_device',
    # #     'host': '192.168.1.100',
    # #     'username': 'user',
    # #     'password': 'password',
    # #     'secret': 'secret',  # if needed for entering privileged mode
    # # }
    # #
    # # with ConnectHandler(**custom_device) as conn:
    # #     # Check if in config mode, if not, enter config mode
    # #     if not conn.check_config_mode():
    # #         conn.config_mode()
    # #     print("Now in configuration mode.")
    # #     # Do configuration tasks...
    # #     # Exit configuration mode
    # #     conn.exit_config_mode()
    # #     print("Exited configuration mode.")