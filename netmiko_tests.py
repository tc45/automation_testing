from netmiko import ConnectHandler, file_transfer
from netmiko.base_connection import BaseConnection
from threading import Thread
import time
from netaddr import IPAddress, IPNetwork


def connect_to_device(device):
    try:
        connection = ConnectHandler(**device)
        print(f"Successfully connected to {device['host']}")
        return connection
    except Exception as e:
        print(f"Failed to connect to {device['host']}: {e}")


def execute_command(connection, command):
    try:
        output = connection.send_command(command)
        return output
    except Exception as e:
        print(f"Failed to execute command: {e}")


def make_configuration_change(connection, commands):
    try:
        connection.enable()  # Ensure in enable mode
        output = connection.send_config_set(commands)
        return output
    except Exception as e:
        print(f"Failed to make configuration change: {e}")
        return "Failed to connect"


def transfer_file(connection, source_file, dest_file, file_action='put'):
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
    connection.session_log = open(log_file, "w")  # Open the log file in write mode
    print(f"Session logging enabled, output will be saved to {log_file}")



def connect_and_execute(device_dictionary, command):
    try:
        with ConnectHandler(**device_dictionary) as conn:
            output = conn.send_command(command)
            print(f"Output from {host}:\n{output}")
    except Exception as e:
        print(f"Failed on {device_dictionary['host']}: {e}")



def device_worker(device, command):
    try:
        with ConnectHandler(**device) as conn:
            output = conn.send_command(command)
            print(f"--- Output from {device['host']} ---\n{output}\n")
    except Exception as e:
        print(f"Failed to connect or execute on {device['host']}: {e}")

def execute_concurrently(devices, command):
    threads = []
    for device in devices:
        thread = Thread(target=device_worker, args=(device, command))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()


def execute_interactive_command(connection, command, expect_string, response):
    """
    Executes an interactive command on a network device.

    Parameters:
    - connection: The Netmiko connection object to the device.
    - command: The command to be executed on the device.
    - expect_string: The string to expect before sending the response. This indicates the command is waiting for user input.
    - response: The response to send when the expect_string is detected.

    Returns:
    - The output of the command execution.
    """
    # Sending the command and waiting for the expected prompt
    output = connection.send_command_timing(command)
    if expect_string in output:
        # The expected prompt was detected, send the response
        output += connection.send_command_timing(response)
    else:
        # If the prompt didn't appear as expected, handle accordingly
        print(f"Expected prompt '{expect_string}' not found in the output.")
    return output


def verify_command_output(connection, command, success_keywords, error_keywords):
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


def show_ip_int_brief_to_cidr(device_params):
    # Create a connection object
    with ConnectHandler(**device_params) as net_connect:
        # Send command to device
        output = net_connect.send_command('show ip int brief', use_textfsm=True)

        # Process each entry in the output
        for entry in output:
            interface = entry['intf']
            ip_address = entry['ipaddr']
            netmask = entry['netmask']

            # Skip entries without an IP address
            if not ip_address or not netmask:
                continue

            # Calculate CIDR notation
            cidr = str(IPNetwork(f"{ip_address}/{netmask}").cidr)

            # Output interface and IP in CIDR notation
            print(f"{interface}: {ip_address}/{cidr}")
        return output


if __name__ == "__main__":
    # Example usage for simple connectivity
    cisco_device = {
        'device_type': 'cisco_ios',
        'host': '192.168.1.233',
        'username': 'cisco',
        'password': 'cisco123',
    }
    cisco_device2 = {
        'device_type': 'cisco_ios',
        'host': '192.168.1.234',
        'username': 'cisco',
        'password': 'cisco123',
    }
    juniper_device = {
        'device_type': 'juniper_junos',
        'host': '192.168.1.3',
        'username': 'admin',
        'password': 'admin123',
    }
    # print("* " * 15 + "Simple Connectivity Example" + " * " * 15)
    # connection = connect_to_device(cisco_device)
    # if connection:
    #     print("Connected successfully!  Disconnecting...")
    #     connection.disconnect()
    #
    #
    # # Example usage for command execution
    # print("* " * 15 + "Simple command execution Example" + " * " * 15)
    # devices = [cisco_device, cisco_device2]
    # start_time = time.time()
    # for device in devices:
    #     connection = connect_to_device(cisco_device)
    #     if connection:
    #         command_output = execute_command(connection, 'show ip interface brief')
    #         connection.disconnect()
    #         print(f"Command output:\n{command_output}")
    # end_time = time.time()
    # duration = end_time - start_time
    # print(f"Execution time: {duration:.2f} seconds")


    # Example usage for text_fsm execution
    print("* " * 15 + "text_fsm command execution Example" + " * " * 15)
    devices = [cisco_device, cisco_device2]
    start_time = time.time()
    for device in devices:
        connection = connect_to_device(cisco_device)
        if connection:
            command_output = show_ip_int_brief_to_cidr(connection)
            connection.disconnect()
            print(f"Command output:\n{command_output}")
    end_time = time.time()
    duration = end_time - start_time
    print(f"Execution time: {duration:.2f} seconds")
    #
    # # Example usage for configuration changes
    # print("* " * 15 + "Multiple command execution Example" + " * " * 15)
    # commands = [
    #     'interface loopback 101',
    #     'ip address 10.1.1.1 255.255.255.255',
    #     'description Netmiko Test Interface',
    #     'no shutdown',
    # ]
    # connection = connect_to_device(cisco_device)
    # if connection:
    #     command_output = make_configuration_change(connection, commands)
    #     connection.disconnect()
    #     print(f"Command output:\n{command_output}")
    #
    # # Example usage for transferring files
    # print("* " * 15 + "Multiple command execution Example" + " * " * 15)
    # source_file = 'test.txt'
    # dest_file = 'test.txt'
    # connection = connect_to_device(cisco_device)
    # if connection:
    #     transfer_file(connection, source_file, dest_file, file_action='put')
    #     connection.disconnect()
    #
    # # Example usage for session logging
    # print("* " * 15 + "Session Logging Example" + " * " * 15)
    # cisco_device = {
    #     'device_type': 'cisco_ios',
    #     'host': '192.168.1.233',
    #     'username': 'cisco',
    #     'password': 'cisco123',
    #     'session_log': 'session_log.txt'
    # }
    #
    # connection = connect_to_device(cisco_device)
    # if connection:
    #     # enable_session_logging(connection)
    #     # Execute some commands to log
    #     connection.send_command("show version")
    #     connection.send_command("show ip interface br")
    #     connection.send_command("show run")
    #     connection.send_command("show blah")
    #     connection.session_log.close()
    #     connection.disconnect()
    #
    # # Multi-vendor support example.
    # print("* " * 15 + "Multiple vendor execution Example" + " * " * 15)
    # # Example usage for a Cisco IOS device
    # connect_and_execute(cisco_device, 'show ip int brief')
    # # Example usage for a Juniper Junos device
    # connect_and_execute(juniper_device, 'show ip int brief')
    #
    # # Example usage - MultiThreading
    # devices = [
    #     cisco_device,
    #     cisco_device2,
    #     # Add more devices as needed
    # ]
    # start_time = time.time()
    # execute_concurrently(devices, "show ip int brief")
    # end_time = time.time()
    # duration = end_time - start_time
    # print(f"Execution time: {duration:.2f} seconds")
    #
    # # Example usage for interactive command using restart as an example
    # print("* " * 15 + "Interactive commands command execution Example" + " * " * 15)
    # start_time = time.time()
    # connection = connect_to_device(cisco_device)
    # if connection:
    #     # Example for a hypothetical 'restart' command that prompts for confirmation
    #     command = 'reload'
    #     expect_string = '[y/n]:'
    #     response = 'y'
    #     output = execute_interactive_command(connection, command, expect_string, response)
    #     print(f"Command execution result:\n{output}")
    #     connection.disconnect()
    # end_time = time.time()
    # duration = end_time - start_time
    # print(f"Execution time: {duration:.2f} seconds")

    # # Example usage for interactive commands
    # connection = connect_to_device(cisco_device)
    # if connection:
    #     execute_interactive_command(connection, 'delete unix:test.txt', 'Confirm', 'y')
    #     connection.disconnect()
    #


    # Example usage for error and keyword detection
    success_keywords = ['completed', 'success']
    error_keywords = ['failed', 'error', 'Invalid']
    connection = connect_to_device(cisco_device)
    if connection:
        verify_command_output(connection, "interface gig 101", success_keywords, error_keywords)
        connection.disconnect()

    # # Register the custom device type
    # ConnectHandler.register_device_type('custom_device', CustomDevice)

    # # Use the custom device
    # custom_device = {
    #     'device_type': 'custom_device',
    #     'host': '192.168.1.100',
    #     'username': 'user',
    #     'password': 'password',
    #     'secret': 'secret',  # if needed for entering privileged mode
    # }
    #
    # with ConnectHandler(**custom_device) as conn:
    #     # Check if in config mode, if not, enter config mode
    #     if not conn.check_config_mode():
    #         conn.config_mode()
    #     print("Now in configuration mode.")
    #     # Do configuration tasks...
    #     # Exit configuration mode
    #     conn.exit_config_mode()
    #     print("Exited configuration mode.")