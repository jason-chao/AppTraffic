import subprocess
import logging
import os
import sys
import re
import random
from enum import Enum

import socket
import netifaces
import ipaddress
from contextlib import closing


logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
docker_image_version = "0.0.1a"


class LaunchMode(Enum):
    """
    Enum for the two launch modes for extenral processes
    """
    Local = 1 # Launched as a local process
    DockerContainer = 2 # Launched in a docker container


class AppTrafficValidator:
    """
    Validator of parameters for external processes
    """
    def __init__(self):
        self.log = logging.getLogger("ValidatorLog")
        pass

    def are_valid_softether_parameter_values(self, *values):
        """
        Checks whether all arguments are valid for SoftEther
        Args:
          *arbitrary arguments
        Returns:
          bool: Ture for passed, False otherwise.
        """
        return all(map(self.is_valid_softether_parameter_value, list(values)))

    def is_valid_softether_parameter_value(self, value):
        """
        Checks whether a value is valid for SoftEther.
        Not all parameters are required to pass the test.
        Non-required parameters should be left as "" and skip this test.

        Args:
           value (str or int): the value
        Returns:
           bool: True for passed, False otherwise.
        """
        if value:
            if type(value) is str:
                if " " not in value: # No space is allowed. Any space in the value would cause confusion in parameter parsing.
                    return True
            if type(value) is int: # Int type is acceptable and will be converted to string in command formatting
                return True
        return False


class SystemOps:
    """
    Process manager
    """
    
    def __init__(self, default_subprocess_timeout=15):
        self.subprocess_timeout = default_subprocess_timeout
        self.log = logging.getLogger("SystemOpsLog")
        pass

    def bash(self, command, timeout_seconds=None):
        """
        Run a command in bash
        Args:
           command (str): the command
           timeout_seconds (int): for how long the process may be killed if unfinished
        Returns:
           str: the text output the command
        """
        if type(timeout_seconds) is not int: 
            timeout_seconds = self.subprocess_timeout  # Use the class's default timeout if timeout_seconds is not specified or invalid
        return subprocess.run(command, check=False, stdout=subprocess.PIPE, shell=True, timeout=timeout_seconds).stdout.decode("utf-8").strip()

    def new_process(self, command: []):
        """
        Start a local process
        Args:
           command (list): the programme and arguments separated as elements in a list
        Returns:
           str: the text output of the process
        """
        return subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def is_root(self):
        """
        Checks if the user is running as root
        Returns:
           bool: True for root, False otherwise.
        """
        return os.getuid() == 0


class ContainerOps:
    """
    Container manager
    """

    def __init__(self, timeout_seconds=30):
        self.sysops = SystemOps()
        self.log = logging.getLogger("ContainerOpsLog")
        self.validator = AppTrafficValidator()
        self.timeout_seconds = timeout_seconds
        pass

    def docker(self, args):
        """
        Launch a docker container
        Args:
           args (str): the argument to be passed on to 'docker' command
        Retruns:
           str: the text output of the docker command
        """
        args = args.replace(":___DOCKER_IMAGE_VERSION___", f":{docker_image_version}")
        return self.sysops.bash("docker %s" % (args), timeout_seconds=self.timeout_seconds)

    def stop_container(self, container_name):
        """
        Stop a docker container
        Args:
           container_name (str): the name of the container to be stopped
        Returns:
           bool: True for container being stopped successfully, False otherwise.
        """
        output = self.docker("stop %s" % (container_name))
        return output if "error" not in output.lower() else None

    def get_container_logs(self, container_name):
        """
        Read the logs of a docker container
        Args:
           container_name (str): the name of the container of which the logs are read
        Returns:
           str: the logs
        """
        return self.sysops.bash("docker logs %s" % (container_name), timeout_seconds=self.timeout_seconds)

    def get_running_containers(self):
        """
        Get the output of dokcer ps -a
        Returns:
           str: the output
        """
        return self.sysops.bash("docker ps -a", timeout_seconds=self.timeout_seconds)


class MITMProxyMode(Enum):
    """
    Enum for the two launch modes for MITMProxy
    """
    ProxyOnly = 1  # launch 'mitmdump' - not 'mitmproxy' because of no console UI interaction
    Web = 2  # launch 'mitmweb'


class NetworkOps:
    """
    Manager of network operations
    """
    def __init__(self):
        pass

    def get_an_unused_local_port(self, range=(0, 1)):
        """
        Get an available network port.
        Derived from code snippet found at https://stackoverflow.com/questions/1365265/on-localhost-how-do-i-pick-a-free-port-number
        Args:
           range (tuple): the lower bound and upper bound of the range for the port; any port if no range is specified.
        Returns:
           int: the available port
        """
        if not isinstance(range[0], int) or not isinstance(range[1], int):
            raise Exception("Invalid range input")
        if range[1] <= range[0]:
            raise Exception("Invalid range")
        while True: # repeat until an available port is found
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                try:
                    sock.bind(("localhost", random.randrange(range[0], range[1])))
                except OSError: # find another port if the port is in use
                    continue
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                unused_port = sock.getsockname()[1]
                return unused_port
        return None

    def get_all_iface_addresses(self):
        """
        Get the the network addresses and masks of the subnets of all network interfaces
        Returns:
           str: Subnet address/subnet mask
        """
        iface_names = netifaces.interfaces()
        iface_addresses = [netifaces.ifaddresses(
                           ifname) for ifname in iface_names]
        iface_afinet_address_lists = [iface_address[netifaces.AF_INET]
                                      for iface_address in iface_addresses if netifaces.AF_INET in iface_address]
        addresses = []
        for iface_afinet_address_list in iface_afinet_address_lists:
            addresses.extend([ipaddress.IPv4Interface(
                f"{afinet_address['addr']}/{afinet_address['netmask']}") for afinet_address in iface_afinet_address_list])
        return addresses


    def create_address_of_subnet(self, subnet: ipaddress.IPv4Network, ipv4addr_part4: int):
        """
        Create an address in a subnet
        Args:
           subnet (ipaddress.IPv4Network): an IPv4 subnet address
           ipv4addr_part4 (int): the last part of an IPv4 address
        Returns:
           str: the IPv4 address created
        """
        if ipv4addr_part4 > 0 and ipv4addr_part4 < 255:
            return re.sub(r"\.0$", ".%s" % (ipv4addr_part4), str(subnet.network_address))
        raise Exception("Invalid address")


    def get_random_unused_subnet(self, exisiting_addresses=[]):
        """
        Generate a random private subnet starting with "10." provided which does not clash with exisiting addresses.  
        Args:
           exisiting_addresses (list): a list of exisiting addresses; if the list is empty, the machine's local addresses would be used.

        """
        if len(exisiting_addresses) == 0:
            exisiting_addresses = self.get_all_iface_addresses()
        ipv4addr_part2 = random.randrange(1, 255)
        ipv4addr_part3 = random.randrange(1, 255)
        ipv4_network = ipaddress.IPv4Network("10.%s.%s.0/24" % (ipv4addr_part2, ipv4addr_part3))
        if any([iface_addr.network == ipv4_network for iface_addr in exisiting_addresses]):
            return self.get_random_unused_subnet(exisiting_addresses)
        return ipv4_network


class RoutingOps:
    """
    Manager of routing operations and operations related to MITMProxy/Web
    """

    def __init__(self, launch_mode: LaunchMode, mitm_mode: MITMProxyMode = None, mitm_ignore_hosts=[], container_ops: ContainerOps = None):
        self.mitm_mode = mitm_mode
        self.launch_mode = launch_mode
        self.mitm_ignore_hosts = mitm_ignore_hosts
        self.log = logging.getLogger("RoutingOpsLog")
        self.sysops = SystemOps()
        self.local_mitm_process = None

        if self.launch_mode is LaunchMode.DockerContainer:
            if type(container_ops) is ContainerOps:
                self.container_ops = container_ops
            else:
                raise ValueError
        elif self.launch_mode is LaunchMode.Local:
            self.local_mitm_process = None

        pass

    def get_ignore_host_arguments(self, hosts=None):
        """
        Get concatenated arguments for the hostnames which should be ignored by MITMProxy for decrypted https 
        Args:
           hosts (list): hostnames to be ignored; the class's default hosts if not specified.
        Retruns:
           str: the concatenated arguments 
        """
        if hosts is None:
            hosts = self.mitm_ignore_hosts
        arguments = " ".join(["--ignore-hosts '^(.+\\.)?%s:443$'" %
                              (host.replace(".", "\\.")) for host in hosts])
        self.log.debug(arguments)
        return arguments

    def launch_mitm(self, output_mitm_file: str, output_har_file: str, proxy_port=None, web_port=None, custom_config_dir=None, volume_mounts=[], internal_interface_ip="10.11.87.1"):
        """
        Launch the MITMProxy/Web
        Args:
           output_mitm_file (str): full path of the mitm log file to be written
           output_har_file (str): full path of the HAR (Http ArcHive) file to be written
           proxy_port (int): the port at which MITMProxy/Web should listen for the proxy service
           web_port (int): the port at which MITMWeb should listen to serve the Web UI
           custom_config_dir (str): the path of the directory containing the CA and configuration files 
           volume_mounts (list of tuples): a list of tuples about the local paths and their mount points on the container, only required in Container mode.
           internal_interface_ip (str): the IP address of this machine at which MITMProxy should listen for the proxy service
        Returns:
           bool: True for a successful launch, False or None otherwise.
        """

        mitm_arguments = "--mode transparent -s /har_dump.py --showhost %s --verbose --listen-host %s --listen-port %s -w %s --set hardump=%s " % (
            self.get_ignore_host_arguments(), internal_interface_ip, proxy_port, output_mitm_file, output_har_file)

        if custom_config_dir:
            mitm_arguments = mitm_arguments + \
                " --set confdir=%s" % (custom_config_dir)

        exec_cmd = None
        if self.mitm_mode is MITMProxyMode.Web:
            mitm_arguments = mitm_arguments + \
                " --web-host 0.0.0.0 --web-port %s" % (web_port)
            exec_cmd = "mitmweb " + mitm_arguments
        elif self.mitm_mode is MITMProxyMode.ProxyOnly:
            exec_cmd = "mitmdump " + mitm_arguments

        self.log.debug(exec_cmd)

        if self.launch_mode is LaunchMode.Local:
            self.local_mitm_process = self.sysops.new_process(
                exec_cmd.split(" "))
            return True
        elif self.launch_mode is LaunchMode.DockerContainer:
            mount_option = " ".join(["-v %s:%s" % (v[0], v[1])
                                     for v in volume_mounts])
            output = self.container_ops.docker(
                "run --name mitm_%s --network host --rm -d -t %s jasonthc/apptraffic-mitmproxy:___DOCKER_IMAGE_VERSION___ %s" % (proxy_port, mount_option, exec_cmd))
            return output if "error" not in output.lower() else None
        return None

    def stop_mitm(self, proxy_port):
        """
        Stop the MITMProxy/Web
        Args:
           proxy_port (int): the port at which the MITMProxy/Web is listening inside a container; not required if MITMProxy/Web was launched locally.
        Returns:
           bool: True for success, False or None otherwise.
        """
        if self.launch_mode is LaunchMode.Local:
            self.local_mitm_process.terminate()
            return True
        elif self.launch_mode is LaunchMode.DockerContainer:
            output = self.container_ops.docker("stop mitm_%s" % (proxy_port))
            return output if "error" not in output.lower() else None
        return None

    def route_traffic_to_mitm(self, interface_internal: str, interface_external: str, proxy_port: int, internal_interface_ip="10.11.87.1", internal_interface_cird="24", undo=False, local_route_traffic_sh_dir="./"):
        """
        Route the packets on a network interface to MITMProxy/Web
        Args:
           interface_internal (str): name of the interface with the traffic being studied
           interface_external (str): name of the interface with an internet gateway
           proxy_port (int): the port at which MITMProxy/Web is listening for the proxy service
           internal_interface_ip (str): the IP address of this machine on the interface handling incoming traffic
           internal_interface_cird (str): the subnet mask in CIRD notation for the interface handling incoming traffic
           undo (bool): undo/remove the routing settings
           local_route_traffic_sh_dir (str): the location of the scripts that change the routing settings, only required in Local mode.
        Returns:
           bool: True for success, False or None otherwise.
        """
        route_arguments = "%sroute_traffic_mitm.sh %s %s %s %s" % ("undo_" if undo else "", "%s/%s" % (
            internal_interface_ip, internal_interface_cird), interface_internal, interface_external, proxy_port)

        if self.launch_mode is LaunchMode.Local:
            exec_cmd = local_route_traffic_sh_dir + route_arguments
            self.local_routing_process = self.sysops.new_process(
                exec_cmd.split(" "))
            return True
        elif self.launch_mode is LaunchMode.DockerContainer:
            exec_cmd = "/routing/" + route_arguments
            output = self.container_ops.docker(
                "run --name routing_mi_%s --rm --network host --cap-add=NET_ADMIN --device=/dev/net/tun -d -t jasonthc/apptraffic-routing:___DOCKER_IMAGE_VERSION___ %s" % (proxy_port, exec_cmd))
            return output if "error" not in output.lower() else None
        return None

    def route_traffic_to_gateway(self, interface_internal: str, interface_external: str, internal_interface_ip="10.11.87.1", internal_interface_cird="24", undo=False, local_route_traffic_sh_dir="./"):
        """
        Route the packets on a network interface to the interface with an internet gateway
        Args:
           interface_internal (str): name of the interface with the traffic being studied
           interface_external (str): name of the interface with an internet gateway
           internal_interface_ip (str): the IP address of this machine on the interface handling incoming traffic
           internal_interface_cird (str): the subnet mask in CIRD notation for the interface handling incoming traffic
           undo (bool): undo/remove the routing settings
           local_route_traffic_sh_dir (str): the location of the scripts that change the routing settings, only required in Local mode.
        Returns:
           bool: True for success, False or None otherwise.
        """
        route_arguments = "%sroute_traffic_gateway.sh %s %s %s" % ("undo_" if undo else "", "%s/%s" % (
            internal_interface_ip, internal_interface_cird), interface_internal, interface_external)

        if self.launch_mode is LaunchMode.Local:
            exec_cmd = local_route_traffic_sh_dir + route_arguments
            self.local_routing_process = self.sysops.new_process(
                exec_cmd.split(" "))
            return True
        elif self.launch_mode is LaunchMode.DockerContainer:
            exec_cmd = "/routing/" + route_arguments
            output = self.container_ops.docker(
                "run --name routing_gw_%s --rm --network host --cap-add=NET_ADMIN --device=/dev/net/tun -d -t jasonthc/apptraffic-routing:___DOCKER_IMAGE_VERSION___ %s" % (interface_internal, exec_cmd))
            return output if "error" not in output.lower() else None
        return None

    def dump_packets(self, output_file: str, interface_internal: str, volume_mounts=[], header_only=False, local_route_traffic_sh_dir="./"):
        """
        Dump/write the network packages on a network interface to a file
        Args:
           output_file (str): the path of the file
           interface_internal (str): name of the interface with the traffic being studied
           volume_mounts (list of tuples): a list of tuples about the local paths and their mount points on the container, only required in Container mode
           header_only (bool): dump the headers of packets (the first 96 bytes) only rather than full packets
           local_route_traffic_sh_dir (str): the location of the scripts that change the routing settings, only required in Local mode
        Returns:
           bool: True for success, False or None otherwise.
        """
        arguments = "intercept_%s.sh %s %s" % (
            "header" if header_only else "raw", interface_internal, output_file)

        if self.launch_mode is LaunchMode.Local:
            exec_cmd = local_route_traffic_sh_dir + arguments
            self.local_dump_process = self.sysops.new_process(
                exec_cmd.split(" "))
            return True
        elif self.launch_mode is LaunchMode.DockerContainer:
            exec_cmd = "/routing/" + arguments
            mount_option = " ".join(["-v %s:%s" % (v[0], v[1])
                                     for v in volume_mounts])
            output = self.container_ops.docker(
                "run --name dump_%s --network host --cap-add=NET_ADMIN --device=/dev/net/tun --rm -d -t %s jasonthc/apptraffic-routing:___DOCKER_IMAGE_VERSION___ %s" % (interface_internal, mount_option, exec_cmd))
            return output if "error" not in output.lower() else None
        return None


class SoftetherOps:
    """
    Manger of operations related to Softether
    Attrs:
       launch_mode (LaunchMode): in which mode Softether will be launched (Container or Local)
       local_vpncmd_path (str): path of the vpncmd programme, only required in Local mode
       container_ops (ContainerOps): an instance of ContainerOps
    """

    def __init__(self, launch_mode: LaunchMode, local_vpncmd_path=None, container_ops: ContainerOps = None):
        self.launch_mode = launch_mode

        if self.launch_mode is LaunchMode.DockerContainer:
            if type(container_ops) is ContainerOps:
                self.container_ops = container_ops
            else:
                raise ValueError
        elif self.launch_mode is LaunchMode.Local:
            if os.path.isfile(local_vpncmd_path):
                self.local_vpncmd_path = local_vpncmd_path
            else:
                raise ValueError
        else:
            raise ValueError

        self.log = logging.getLogger("SoftetherOpsLog")
        self.sysops = SystemOps()
        self.validator = AppTrafficValidator()
        pass

    def deploy_entry_node(self, container_name):
        """
        Start a container of Softether to serve as the Entry Node
        Args:
           container_name: name of the container
        Returns:
           bool: True for success, False or None otherwise
        """
        if self.launch_mode is not LaunchMode.DockerContainer:
            raise Exception("Container mode only")
        output = self.container_ops.docker("run --name %s --network host --rm -d -t jasonthc/apptraffic-softether-vpnserver:___DOCKER_IMAGE_VERSION___" %
                                           (container_name))
        return output if "error" not in output.lower() else None

    def deploy_exit_node(self, container_name):
        """
        Start a container of Softether to serve as the Exit Node
        Args:
           container_name: name of the container
        Returns:
           bool: True for success, False or None otherwise
        """
        if self.launch_mode is not LaunchMode.DockerContainer:
            raise Exception("Container mode only")
        output = self.container_ops.docker("run --name %s --network host --cap-add=NET_ADMIN --device=/dev/net/tun --rm -d -t jasonthc/apptraffic-softether-vpnserver:___DOCKER_IMAGE_VERSION___" %
                                           (container_name))
        return output if "error" not in output.lower() else None

    def vpncmd(self, cmd, host="localhost", port=5555, password="", hub="", timeout_seconds=10):
        """
        Run a Softether command to configure Softether using the vpncmd tool
        Args:
           cmd (str): the Softether command
           host (str): the hostname of the Softether server
           port (int): the port at which the Softether server is listening
           password (str): the administrative password of the Softether server or the Hub
           hub (str): the Softether hub to mangae; left blank if the target is the server
           timeout_seconds (int): the seconds to wait for before terminating an unresponsive process
        Returns: 
           str: the output of the vpncmd executing the command
        """
        if cmd and host and port: # Softether allows the use of an empty password in localhost connections so no need to check the password
            vpncmd_arguments = "%s:%s /SERVER /HUB:%s /PASSWORD:%s /cmd:%s" % (
                host, port, hub, password, cmd) # the password parameter may for either the server or the hub, depending on the hub parameter
            output = None

            if self.launch_mode is LaunchMode.DockerContainer:
                output = self.container_ops.docker(
                    "run --network host --rm jasonthc/apptraffic-softether-vpncmd:___DOCKER_IMAGE_VERSION___ timeout %ss /usr/local/vpnclient/vpncmd %s" % (timeout_seconds, vpncmd_arguments))
            elif self.launch_mode is LaunchMode.Local:
                output = self.sysops.bash("%s %s" % (
                    self.local_vpncmd_path, vpncmd_arguments))

            self.log.debug(output)
            return output
        raise ValueError

    def batch_vpncmd(self, cmd_list, host="localhost", port=5555, password="", hub=""):
        """
        Run a batch of Softether commands to configure Softether using the vpncmd tool
        Args:
           cmd_list (list): a list of Softether commands
           host (str): see method 'vpncmd'
           port (int): see method 'vpncmd'
           password (str): see method 'vpncmd'
           hub (str): see method 'vpncmd'
        Returns: 
           dict:
              key: the command
              value: the output of vpncmd executing the command
        """
        outputs = {}
        for full_cmd in cmd_list:
            cmd_key = full_cmd.split(" ")[0]
            outputs[cmd_key] = self.vpncmd(
                full_cmd, host=host, port=port, password=password, hub=hub)
        return outputs

    def is_vpncmd_output_successful(self, command_output):
        """
        Check if the output of vpncmd suggests the successful execution of an command
        Args:
           command_output (str): the output of vpncmd
        Returns:
           bool: True for success, False otherwise.
        """
        return "command completed successfully" in command_output.lower()

    def are_vpncmd_outputs_successful(self, command_outputs):
        """
        Check the output of vpncmd if all commands have been successful
        Args:
           command_output (list): a list of output of vpncmd
        Returns:
           bool: True for successful executions, False otherwise.
        """
        return all(map(self.is_vpncmd_output_successful, [command_outputs[cmd_key] for cmd_key in command_outputs.keys()]))

    def set_server_password(self, new_server_password: str, exisiting_server_password="", host="localhost", port=5555):
        """
        Set the administrative password of the Softether server
        Args:
           new_server_password (str): the new password
           exisiting_server_password (str): the old password
           host (str): see method 'vpncmd'
           port (int): see method 'vpncmd'
        Returns:
           bool: True for successful execution, False otherwise
        """
        if self.validator.are_valid_softether_parameter_values(new_server_password, host, port):
            output = self.vpncmd("ServerPasswordSet %s" % (
                new_server_password), host=host, port=port, password=exisiting_server_password, hub="")
            return self.is_vpncmd_output_successful(output)
        raise ValueError

    def create_hub(self, new_hub: str, new_hub_password: "", host="localhost", port=5555, server_password=""):
        """
        Create a new virtual hub on the Softether server
        Args:
           new_hub (str): name of the new hub
           new_hub_password (str): password of the new hub
           host (str): see method 'vpncmd'
           port (int): see method 'vpncmd'
           password (str): see method 'vpncmd'
        Returns:
           bool: True for successful execution, False otherwise
        """
        if self.validator.are_valid_softether_parameter_values(new_hub, host, port):
            output = self.vpncmd("HubCreate %s /PASSWORD:%s" % (
                new_hub, new_hub_password), host=host, port=port, password=server_password)
            return self.is_vpncmd_output_successful(output)
        raise ValueError

    def delete_hub(self, hub: str, host="localhost", port=5555, server_password=""):
        """
        Delete a hub on the Softether server
        Args:
           hub (str): name of the hub to be delted
           host (str): see method 'vpncmd'
           port (int): see method 'vpncmd'
           password (str): see method 'vpncmd'
        Returns:
           bool: bool: True for successful execution, False otherwise
        """
        if self.validator.are_valid_softether_parameter_values(hub, host, port):
            output = self.vpncmd("HubDelete %s" % (
                hub), host=host, port=port, password=server_password)
            return self.is_vpncmd_output_successful(output)
        raise ValueError

    def delete_listening_port(self, listening_port: int, host="localhost", port=5555, server_password=""):
        """
        Delete a port to which the Softether server is listening
        Args:
           listening_port (int): the port number
           host (str): see method 'vpncmd'
           port (int): see method 'vpncmd'
           password (str): see method 'vpncmd'
        Returns:
           bool: bool: True for successful execution, False otherwise
        """
        if self.validator.are_valid_softether_parameter_values(listening_port, host, port):
            output = self.vpncmd("ListenerDelete %s" % (
                listening_port), host=host, port=port, password=server_password)
            return self.is_vpncmd_output_successful(output)
        raise ValueError

    def set_server_IpSec(self, pre_shared_key: str, host="localhost", port=5555, server_password=""):
        """
        Set the pre-shared key for IPsec VPN connections
        Args:
           listening_port (int): the port number
           host (str): see method 'vpncmd'
           port (int): see method 'vpncmd'
           password (str): see method 'vpncmd'
        Returns:
           bool: bool: True for successful execution, False otherwise
        """
        if self.validator.are_valid_softether_parameter_values(pre_shared_key, host, port):
            pre_shared_key = str(pre_shared_key)
            key_length = len(pre_shared_key)
            # softether recommends that the length of the key is < 10 due to an Android bug
            if key_length > 0 and key_length <= 9:
                output = self.vpncmd("IPSecEnable /L2TP:yes /PSK:%s /DEFAULTHUB:DEFAULT /L2TPRAW:no /ETHERIP:no" %
                                     (pre_shared_key),  host=host, port=port, password=server_password)
                return self.is_vpncmd_output_successful(output)
        raise ValueError

    def init_entry_node_hub(self, hub: str, hub_password="", host="localhost", port=5555):
        """
        Initialise an entry hub on the SoftEther server
        Args:
           hub (str): the name for the entry hub
           host (str): see method 'vpncmd'
           port (int): see method 'vpncmd'
           password (str): see method 'vpncmd'
        Returns:
           bool: bool: True for successful execution, False otherwise
        """
        if self.validator.are_valid_softether_parameter_values(hub, host, port):
            outputs = self.batch_vpncmd(["NatDisable", "DhcpDisable", "SecureNatDisable"],
                                        host=host, port=port, password=hub_password, hub=hub)
            return self.are_vpncmd_outputs_successful(outputs)
        raise ValueError

    def add_user_to_hub(self, username: str, user_password: str, hub: str, hub_password="", host="localhost", port=5555):
        """
        Add a new user to an SoftEther server hub
        Args:
           username (str): the username of the new user
           user_password (str): the password of the new user
           hub (str): the hub to which the user is added
           hub_password (str): see method 'vpncmd'
           host (str): see method 'vpncmd'
           port (int): see method 'vpncmd'
        Returns:
           bool: bool: True for successful execution, False otherwise
        """
        if self.validator.are_valid_softether_parameter_values(hub, username, user_password, host, port):

            outputs = self.batch_vpncmd(["UserCreate %s /GROUP: /REALNAME:%s /NOTE:" % (username, username),
                                         "UserPasswordSet %s /PASSWORD:%s" % (username, user_password)],
                                        host=host, port=port, password=hub_password, hub=hub)
            return self.are_vpncmd_outputs_successful(outputs)
        raise ValueError

    def remove_user_from_hub(self, username: str, hub: str, hub_password="", host="localhost", port=5555):
        """
        Add a new user to an SoftEther server hub
        Args:
           username (str): the username of the new user
           user_password (str): the password of the new user
           hub (str): the hub to which the user is added
           hub_password (str): see method 'vpncmd'
           host (str): see method 'vpncmd'
           port (int): see method 'vpncmd'
        Returns:
           bool: bool: True for successful execution, False otherwise
        """
        if self.validator.are_valid_softether_parameter_values(hub, username, host, port):
            userdelete_output = self.vpncmd("UserDelete %s" % (
                username), host=host, port=port, password=hub_password, hub=hub)
            return self.is_vpncmd_output_successful(userdelete_output)
        raise ValueError

    def init_exit_node_hub(self, hub: str, hub_password="", host="localhost", port=5555,
                           dhcp_start="10.11.87.100", dhcp_end="10.11.87.200", dhcp_subnet_mask="255.255.255.0",
                           dhcp_gateway="10.11.87.1", dhcp_dns1="8.8.8.8", dhcp_dns2="1.1.1.1", dhcp_expiry=7200,
                           interface_ip="10.11.87.2"):
        """
        Initialise an entry hub on the SoftEther server
        Args:
           hub (str): the name for the entry hub
           user_password (str): the password of the new user
           host (str): see method 'vpncmd'
           port (int): see method 'vpncmd'
           dhcp_start (str): the start of the range of IP address assignment using DHCP 
           dhcp_end (str): the end of the range of IP address assignment using DHCP 
           
        Returns:
           bool: bool: True for successful execution, False otherwise
        """
        if self.validator.are_valid_softether_parameter_values(hub, host, port):
            outputs = self.batch_vpncmd(["NatDisable",
                                         "DhcpSet /START:%s /END:%s /MASK:%s /EXPIRE:%s /GW:%s /DNS:%s /DNS2:%s /DOMAIN: /LOG:no" %
                                         (dhcp_start, dhcp_end, dhcp_subnet_mask,
                                          dhcp_expiry, dhcp_gateway, dhcp_dns1, dhcp_dns2),
                                         "SecureNatHostSet /MAC: /IP:%s /MASK:%s" % (
                                             interface_ip, dhcp_subnet_mask),
                                         "SecureNatEnable"
                                         ], host=host, port=port, password=hub_password, hub=hub)
            return self.are_vpncmd_outputs_successful(outputs)
        raise ValueError

    def connect_exit_node_to_entry_node(self, exit_hub: str, entry_hub: str, entry_hub_username: str, entry_hub_user_password: str, exit_hub_password="",
                                        exit_host="localhost", exit_port=5555, entry_host="localhost", entry_port=5555, cascade_connection_name="VPNEntryNode"):
        if self.validator.are_valid_softether_parameter_values(exit_hub, entry_hub, entry_hub_username, entry_hub_user_password, cascade_connection_name):
            outputs = self.batch_vpncmd(["CascadeCreate %s /SERVER:%s:%s /HUB:%s /USERNAME:%s" % (cascade_connection_name, entry_host, entry_port, entry_hub, entry_hub_username),
                                         "CascadePasswordSet %s /PASSWORD:%s /TYPE:standard" % (
                                             cascade_connection_name, entry_hub_user_password),
                                         "CascadeOnline %s" % (
                                             cascade_connection_name)
                                         ], host=exit_host, port=exit_port, password=exit_hub_password, hub=exit_hub)
            return self.are_vpncmd_outputs_successful(outputs)
        return ValueError

    def disconnect_exit_node_and_entry_node(self, exit_hub: str, exit_hub_password="", exit_host="localhost", exit_port=5555, cascade_connection_name="VPNEntryNode"):
        if self.validator.are_valid_softether_parameter_values(exit_hub):
            outputs = self.batch_vpncmd(["CascadeOffline %s" % (cascade_connection_name),
                                         "CascadeDelete %s" % (
                                             cascade_connection_name)
                                         ], host=exit_host, port=exit_port, password=exit_hub_password, hub=exit_hub)
            return self.are_vpncmd_outputs_successful(outputs)
        raise ValueError

    def bridge_hub_and_tap(self, tap_name: str, hub: str, host="localhost", port=5555, server_password=""):
        if self.validator.are_valid_softether_parameter_values(tap_name, hub):
            outputs = self.batch_vpncmd(["BridgeCreate %s /DEVICE:%s /TAP:yes" % (hub, tap_name),
                                         "BridgeList" % ()],
                                        host=host, port=port, password=server_password)
            return self.are_vpncmd_outputs_successful(outputs) and "operating" in outputs["BridgeList"].lower()
        raise ValueError

    def remove_bridge(self, tap_name: str, hub: str, host="localhost", port=5555, server_password=""):
        if self.validator.are_valid_softether_parameter_values(tap_name, hub):
            output = self.vpncmd("BridgeDelete %s /DEVICE:%s" %
                                 (hub, tap_name), host=host, port=port, password=server_password)
            return self.is_vpncmd_output_successful(output)
        raise ValueError

    def list_hubs(self, host="localhost", port=5555, server_password=""):
        output = self.vpncmd("HubList", host=host,
                             port=port, password=server_password)
        output_lines = output.split("\n")
        hub_list = list([l.split("|")[1].strip()
                         for l in output_lines if "Virtual Hub Name" in l])
        return hub_list
