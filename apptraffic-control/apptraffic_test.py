# import pytest
import unittest
import logging
import os
import sys
import ipaddress
import random
import socket
from contextlib import closing


from apptraffic import SystemOps, ContainerOps, SoftetherOps, RoutingOps, AppTrafficValidator, LaunchMode, MITMProxyMode, NetworkOps

softether_test_host = "127.0.0.1"

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)


def user_is_root():
    return os.getuid() == 0


def is_local(host):
    return host in ["127.0.0.1", "localhost"]


class TestValidator(unittest.TestCase):
    def setUp(self):
        self.validator = AppTrafficValidator()
        pass

    def test_is_valid_softether_parameter_value(self):
        # an empty string or None should not be validated
        self.assertFalse(self.validator.is_valid_softether_parameter_value(""))
        self.assertFalse(
            self.validator.is_valid_softether_parameter_value(None))
        # value with a space in any position should not be validated
        self.assertFalse(
            self.validator.is_valid_softether_parameter_value(" "))
        self.assertFalse(
            self.validator.is_valid_softether_parameter_value("the value"))
        self.assertFalse(
            self.validator.is_valid_softether_parameter_value(" the_value"))
        self.assertFalse(
            self.validator.is_valid_softether_parameter_value("the_value "))
        # only non-empty strings without any space and numbers are accepted
        self.assertTrue(
            self.validator.is_valid_softether_parameter_value("the_value"))
        self.assertTrue(
            self.validator.is_valid_softether_parameter_value(12345))
        pass

    # test passing multiple arguments
    def test_are_valid_softether_parameter_values(self):
        self.assertFalse(
            self.validator.are_valid_softether_parameter_values("value_a", "value b"))
        self.assertTrue(self.validator.are_valid_softether_parameter_values(
            "a_value", "localhost", 5555))
        pass


class TestNetworkOps(unittest.TestCase):
    def setUp(self):
        self.networkOps = NetworkOps()
        pass

    def test_get_an_unused_local_port(self):
        unused_port_without_specified_range = self.networkOps.get_an_unused_local_port()
        self.assertIsNotNone(unused_port_without_specified_range)
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.bind(("localhost", unused_port_without_specified_range))
            new_port = self.networkOps.get_an_unused_local_port(range=(
                unused_port_without_specified_range, unused_port_without_specified_range+2))
            self.assertNotEqual(unused_port_without_specified_range, new_port)
        self.assertTrue(isinstance(unused_port_without_specified_range, int))
        print("Unused port with a specified range: %s" %
              (unused_port_without_specified_range))
        with self.assertRaises(Exception):
            self.networkOps.get_an_unused_local_port(range=None)
        with self.assertRaises(Exception):
            self.networkOps.get_an_unused_local_port(
                range=("invalid_input", "invalid_input"))
        range_start = 44100
        range_stop = 44200
        with self.assertRaises(Exception):
            self.networkOps.get_an_unused_local_port(
                range=(range_stop, range_start))
        unused_port_in_range = self.networkOps.get_an_unused_local_port(
            range=(range_start, range_stop))
        self.assertTrue(range_start <= unused_port_in_range < range_stop)
        self.assertIsNotNone(unused_port_in_range)
        self.assertTrue(isinstance(unused_port_in_range, int))
        print("Unused port in a specified range: %s" % (unused_port_in_range))
        pass

    def test_create_address_of_subnet(self):
        network = ipaddress.IPv4Network("10.11.87.0/24")
        with self.assertRaises(Exception):
            self.networkOps.create_address_of_subnet(network, 0)
        with self.assertRaises(Exception):
            self.networkOps.create_address_of_subnet(network, 255)
        address_str = self.networkOps.create_address_of_subnet(
            network, random.randrange(1, 255))
        address = ipaddress.IPv4Address(address_str)
        self.assertTrue(isinstance(address, ipaddress.IPv4Address))
        print("Generated address of subnet: %s" % str(address))
        pass


class TestSystemOps(unittest.TestCase):
    def setUp(self):
        self.ops = SystemOps()
        self.log = logging.getLogger("TestSystemOpsLog")
        pass

    def test_bash(self):
        self.assertEqual(self.ops.bash("echo 'AppTraffic'"), "AppTraffic")
        pass

    @unittest.skipUnless(user_is_root(), "requires root privileges")
    def test_is_root(self):
        self.assertTrue(self.ops.is_root())
        pass


class TestContainerOps(unittest.TestCase):

    def setUp(self):
        self.ops = ContainerOps()
        pass

    def test_docker(self):
        self.assertTrue(self.ops.docker(
            "--version").startswith("Docker version "))
        pass


class TestMITMProxyOps(unittest.TestCase):

    def setUp(self):
        self.log = logging.getLogger("TestMITMProxyOpsLog")
        pass

    def test_generate_ignore_host_arguments(self):
        proxy_ops = RoutingOps(mitm_mode=MITMProxyMode.ProxyOnly,
                               launch_mode=LaunchMode.Local, mitm_ignore_hosts=[])
        # Use the host names passed to the class constructor
        self.assertEqual(proxy_ops.get_ignore_host_arguments(hosts=None), "")
        hosts = ["apple.com", "icloud.com"]
        # Pass host names to the function directly
        arguments = proxy_ops.get_ignore_host_arguments(hosts=hosts)
        self.assertEqual(
            arguments, "--ignore-hosts '^(.+\\.)?apple\\.com:443$' --ignore-hosts '^(.+\\.)?icloud\\.com:443$'")
        pass

    def test_launch_mitmproxy(self):
        proxy_ops = RoutingOps(mitm_mode=MITMProxyMode.ProxyOnly, launch_mode=LaunchMode.DockerContainer,
                               container_ops=ContainerOps(), mitm_ignore_hosts=["apple.com", "icloud.com"])
        networkops = NetworkOps()
        proxy_port = networkops.get_an_unused_local_port()
        output = proxy_ops.launch_mitm(
            output_mitm_file="/tmp/test.mitm", output_har_file="/tmp/test.har", proxy_port=proxy_port)
        self.log.debug(output)
        pass

    def test_launch_mitmweb(self):
        proxy_ops = RoutingOps(mitm_mode=MITMProxyMode.Web, launch_mode=LaunchMode.DockerContainer,
                               container_ops=ContainerOps(), mitm_ignore_hosts=["apple.com", "icloud.com"])
        networkops = NetworkOps()
        proxy_port = networkops.get_an_unused_local_port()
        web_port = networkops.get_an_unused_local_port()
        output = proxy_ops.launch_mitm(output_mitm_file="/tmp/test.mitm",
                                       output_har_file="/tmp/test.har", proxy_port=proxy_port, web_port=web_port)
        self.log.debug(output)
        pass


@unittest.skipUnless(user_is_root() and is_local(softether_test_host), "requires root privileges")
class TestLocalDockerSoftetherOps(unittest.TestCase):

    def setUp(self):
        self.ops = SoftetherOps(
            launch_mode=LaunchMode.DockerContainer, container_ops=ContainerOps())
        self.log = logging.getLogger("TestSoftetherOpsLog")
        self.test_host = softether_test_host
        self.test_current_server_password = "test_server_password"
        self.test_entry_hub = "dummy_entry_hub"
        self.test_exit_hub = "dummy_exit_hub"
        self.test_hub_password = "dummy_hub_password"
        self.test_username = "test_user"
        self.test_password = "test_password"
        self.test_softether_container_name = "test_vpnserver"
        self.test_bridge_tap_name = "inspect"

        container_id_created = self.ops.deploy_entry_node(
            self.test_softether_container_name)
        self.assertIsNotNone(container_id_created)
        pass

    def test_deploy_softether(self):

        with self.subTest("Set password"):
            self.assertTrue(self.ops.set_server_password(
                new_server_password=self.test_current_server_password, exisiting_server_password="", host=self.test_host))

        with self.subTest("Set IpSec"):
            self.assertTrue(self.ops.set_server_IpSec(
                "abcdefghi", host=self.test_host, server_password=self.test_current_server_password))
            self.assertTrue(self.ops.set_server_IpSec(
                123456789, host=self.test_host, server_password=self.test_current_server_password))

        with self.subTest("Create and initialise entry hub"):
            self.assertTrue(self.ops.create_hub(new_hub=self.test_entry_hub, new_hub_password=self.test_hub_password,
                                                host=self.test_host, server_password=self.test_current_server_password))
            self.assertTrue(self.ops.init_entry_node_hub(
                hub=self.test_entry_hub, host=self.test_host, hub_password=self.test_hub_password))

        with self.subTest("Create and initialise exit hub"):
            self.assertTrue(self.ops.create_hub(new_hub=self.test_exit_hub, new_hub_password=self.test_hub_password,
                                                host=self.test_host, server_password=self.test_current_server_password))
            self.assertTrue(self.ops.init_exit_node_hub(
                hub=self.test_exit_hub, host=self.test_host, hub_password=self.test_hub_password))

        with self.subTest("List hubs"):
            hubs = self.ops.list_hubs(
                host=self.test_host, server_password=self.test_current_server_password)
            self.assertTrue("dummy_entry_hub" in hubs)
            self.assertTrue("dummy_exit_hub" in hubs)
            self.log.debug(hubs)

        with self.subTest("Get server info"):
            self.assertTrue(self.ops.vpncmd(
                "ServerInfoGet", host=self.test_host, password=self.test_current_server_password))

        with self.subTest("Add user to Entry Hub"):
            self.assertTrue(self.ops.add_user_to_hub(username=self.test_username, user_password=self.test_password,
                                                     hub=self.test_entry_hub, host=self.test_host, hub_password=self.test_hub_password))

        with self.subTest("Connect Exit Node to Entry Node"):
            self.assertTrue(self.ops.connect_exit_node_to_entry_node(exit_hub=self.test_exit_hub, entry_hub=self.test_entry_hub, entry_hub_username=self.test_username,
                                                                     entry_hub_user_password=self.test_password, exit_hub_password=self.test_hub_password, exit_host=self.test_host, entry_host=self.test_host))

        with self.subTest("Disconnect Exit Node and Entry Node"):
            self.ops.disconnect_exit_node_and_entry_node(
                exit_hub=self.test_exit_hub, exit_hub_password=self.test_hub_password, exit_host=self.test_host)

        with self.subTest("Remove user from Entry Hub"):
            self.assertTrue(self.ops.remove_user_from_hub(username=self.test_username,
                                                          hub=self.test_entry_hub, host=self.test_host, hub_password=self.test_hub_password))

        with self.subTest("Remove Hubs"):
            self.assertTrue(self.ops.delete_hub(
                hub=self.test_exit_hub, host=self.test_host, server_password=self.test_current_server_password))
            self.assertTrue(self.ops.delete_hub(hub=self.test_entry_hub,
                                                host=self.test_host, server_password=self.test_current_server_password))
        pass

    def test_wrong_server_password(self):
        self.assertFalse(self.ops.vpncmd(
            "ServerInfoGet", host=self.test_host, password="wrong_password"))

    def test_failed_connection(self):
        self.assertFalse(self.ops.vpncmd(
            "ServerInfoGet", host="invalid_hostname", password="no_password"))

    def test_setIpSec_errors(self):
        with self.assertRaises(ValueError):
            self.ops.set_server_IpSec("")
        with self.assertRaises(ValueError):
            self.ops.set_server_IpSec(" ")
        with self.assertRaises(ValueError):
            self.ops.set_server_IpSec(None)
        with self.assertRaises(ValueError):
            self.ops.set_server_IpSec("0123456789")
        pass

    def tearDown(self):
        container_id_stopped = self.ops.container_ops.stop_container(
            self.test_softether_container_name)
        self.assertEqual(container_id_stopped,
                         self.test_softether_container_name)


if __name__ == '__main__':
    unittest.main()
