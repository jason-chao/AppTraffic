#!/usr/bin/env python3

import redis
import argparse
import json
import configparser
import shutil
import os
import threading
import datetime
import time
import gc

from apptraffic import *
from coordination import CoordinationPubSubMessageType


logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)


class Machine:

    def __init__(self, launch_mode: LaunchMode, machine_config: {}):
        self.log = logging.getLogger("MachineLog")
        self.launch_mode = launch_mode
        self.machine_config = machine_config
        self.config = {}
        self.config["softether_container_creation_timeout_s"] = 60
        pass

    def wait_until_softher_container_ready(self, container_name):
        container_ops = ContainerOps()
        start_time = datetime.datetime.utcnow()
        while (datetime.datetime.utcnow() - start_time) < datetime.timedelta(seconds=self.config["softether_container_creation_timeout_s"]):
            if container_name in container_ops.get_running_containers():
                if "service has been started" in container_ops.get_container_logs(container_name).lower():
                    return True
            time.sleep(1)
        return False

    def start_entry_node(self):

        softether_ops = SoftetherOps(
            launch_mode=self.launch_mode, container_ops=ContainerOps())

        container_name = "softether_entry"
        softether_ops.deploy_entry_node(container_name)

        if not self.wait_until_softher_container_ready(container_name):
            raise Exception(
                "The Softether Service for the entry node could not be created")

        softether_password = self.machine_config["Entry_Node"]["softether_password"]
        self.log.debug(softether_password)
        softether_vpn_psk = self.machine_config["Entry_Node"]["softether_vpn_l2tp_psk"]
        self.log.debug(softether_vpn_psk)

        softether_ops.set_server_password(
            new_server_password=softether_password)
        softether_ops.set_server_IpSec(
            pre_shared_key=softether_vpn_psk, server_password=softether_password)
        softether_ops.delete_listening_port(
            443, server_password=softether_password)

        pass

    def start_exit_node(self):

        softether_ops = SoftetherOps(
            launch_mode=self.launch_mode, container_ops=ContainerOps())

        container_name = "softether_exit"
        softether_ops.deploy_exit_node(container_name)

        if not self.wait_until_softher_container_ready(container_name):
            raise Exception(
                "The Softether Service for the entry node could not be created")

        softether_password = self.machine_config["Exit_Node"]["softether_password"]
        self.log.debug(softether_password)

        softether_ops.set_server_password(
            new_server_password=softether_password)
        softether_ops.delete_listening_port(
            443, server_password=softether_password)

        pass

    def stop_entry_node(self):
        self.stop_container("softether_entry")
        pass

    def stop_exit_node(self):
        self.stop_container("softether_exit")
        pass

    def stop_container(self, container_name):
        if self.launch_mode == LaunchMode.DockerContainer:
            container_ops = ContainerOps()
            return container_ops.docker("stop %s" % (container_name))
        elif self.launch_mode == LaunchMode.Local:
            raise Exception("Local LaunchMode is not supported")
        pass

    def hub_exists(self, hub_name):

        softether_ops = SoftetherOps(
            launch_mode=self.launch_mode, container_ops=ContainerOps())

        softether_password = self.machine_config["Entry_Node"]["softether_password"]
        hubs = softether_ops.list_hubs(server_password=softether_password)

        return (hub_name in hubs)

    def delete_hub_if_exists(self, hub_name):

        if self.hub_exists(hub_name):
            softether_ops = SoftetherOps(
                launch_mode=self.launch_mode, container_ops=ContainerOps())
            softether_password = self.machine_config["Entry_Node"]["softether_password"]
            self.log.debug("Deleting Hub %s as it already exists" & (hub_name))
            return softether_ops.delete_hub(hub=hub_name, server_password=softether_password)

        return True

    def new_session_on_entry_node(self, entry_hub_name, entry_hub_password, vpn_username, vpn_password, cascade_username, cascade_password):

        softether_ops = SoftetherOps(
            launch_mode=self.launch_mode, container_ops=ContainerOps())

        softether_password = self.machine_config["Entry_Node"]["softether_password"]

        self.delete_hub_if_exists(entry_hub_name)

        if softether_ops.create_hub(
                new_hub=entry_hub_name, new_hub_password=entry_hub_password, server_password=softether_password) is False:
            raise Exception("Could not create the Entry Hub")

        if softether_ops.init_entry_node_hub(
                hub=entry_hub_name, hub_password=entry_hub_password) is False:
            raise Exception("Could not initialise the Entry Hub")

        # add an user for the smartphone's access to the VPN
        if softether_ops.add_user_to_hub(
                username=vpn_username, user_password=vpn_password, hub=entry_hub_name, hub_password=entry_hub_password) is False:
            raise Exception("Could not add VPN user to the Entry Hub")

        # add an user for the Exit Node's cacade connection
        if softether_ops.add_user_to_hub(
                username=cascade_username, user_password=cascade_password, hub=entry_hub_name, hub_password=entry_hub_password) is False:
            raise Exception(
                "Could not add cascade connection user to the Entry Hub")

        return True

    def setup_exit_hub(self, subnet: ipaddress.IPv4Network, exit_hub_name, exit_hub_password, entry_node_hostname, entry_hub_name, cascade_username, cascade_password, tap_suffix):

        softether_ops = SoftetherOps(
            launch_mode=self.launch_mode, container_ops=ContainerOps())

        softether_password = self.machine_config["Exit_Node"]["softether_password"]

        self.delete_hub_if_exists(entry_hub_name)

        if softether_ops.create_hub(
                new_hub=exit_hub_name, new_hub_password=exit_hub_password, server_password=softether_password) is False:
            raise Exception("Could not create the Exit Hub")

        network_ops = NetworkOps()

        dhcp_start = network_ops.create_address_of_subnet(
            subnet=subnet, ipv4addr_part4=100)
        dhcp_end = network_ops.create_address_of_subnet(
            subnet=subnet, ipv4addr_part4=200)
        dhcp_gateway = network_ops.create_address_of_subnet(
            subnet=subnet, ipv4addr_part4=1)
        interface_ip = network_ops.create_address_of_subnet(
            subnet=subnet, ipv4addr_part4=2)
        dhcp_subnet_mask = str(subnet.netmask)

        if softether_ops.init_exit_node_hub(
                hub=exit_hub_name, hub_password=exit_hub_password, dhcp_start=dhcp_start, dhcp_end=dhcp_end, dhcp_gateway=dhcp_gateway, dhcp_subnet_mask=dhcp_subnet_mask, interface_ip=interface_ip) is False:
            raise Exception("Could not initialise the Exit Hub")

        if softether_ops.connect_exit_node_to_entry_node(exit_hub=exit_hub_name, entry_hub=entry_hub_name, entry_hub_username=cascade_username,
                                                         entry_hub_user_password=cascade_password, exit_hub_password=exit_hub_password, entry_host=entry_node_hostname) is False:
            raise Exception("Could not connect the Exit Hub to the Entry Hub")

        if softether_ops.bridge_hub_and_tap(
                tap_name=tap_suffix, hub=exit_hub_name, server_password=softether_password) is False:
            raise Exception("Could not setup bridging")

        return True

    def new_dump_session_on_exit_node(self, exit_hub_name, exit_hub_password, entry_node_hostname, entry_hub_name, cascade_username, cascade_password, intercept_mode, tap_suffix, session_data_subfolder):

        if intercept_mode not in ["raw", "metadata"]:
            raise Exception("Invalid intercept mode")

        sys_ops = SystemOps()
        network_ops = NetworkOps()
        subnet = network_ops.get_random_unused_subnet()

        self.setup_exit_hub(subnet=subnet, exit_hub_name=exit_hub_name, exit_hub_password=exit_hub_password, entry_node_hostname=entry_node_hostname,
                            entry_hub_name=entry_hub_name, cascade_username=cascade_username, cascade_password=cascade_password, tap_suffix=tap_suffix)

        # work should continue here
        routing_ops = RoutingOps(
            launch_mode=self.launch_mode, container_ops=ContainerOps())

        dump_data_path = os.path.join(
            self.machine_config["Stoarge"]["session_data_path"], session_data_subfolder)

        sys_ops.bash("rm -rf %s && mkdir -p %s" %
                     (dump_data_path, dump_data_path))

        volume_mounts = [(dump_data_path, "/host/data/")]

        header_only = False if intercept_mode == "raw" else True

        if routing_ops.dump_packets(output_file="/host/data/session_traffic.pcap", volume_mounts=volume_mounts, interface_internal="tap_%s" % (tap_suffix), header_only=header_only) is False:
            raise Exception("Could not dump traffic")

        internal_interface_ip = network_ops.create_address_of_subnet(
            subnet=subnet, ipv4addr_part4=1)
        internal_interface_cird = subnet.prefixlen
        if routing_ops.route_traffic_to_gateway(interface_internal="tap_%s" % (tap_suffix), interface_external=self.machine_config["Exit_Node"]["gateway_interface"], internal_interface_ip=internal_interface_ip, internal_interface_cird=internal_interface_cird) is False:
            raise Exception("Could not route traffic to gateway")

        return {"subnet": str(subnet)}

    def new_mitm_session_on_exit_node(self, exit_hub_name, exit_hub_password, entry_node_hostname, entry_hub_name, cascade_username, cascade_password, mitm_ca, mitm_ca_cert, session_data_subfolder):

        sys_ops = SystemOps()
        network_ops = NetworkOps()

        proxy_port = network_ops.get_an_unused_local_port()
        web_port = network_ops.get_an_unused_local_port()
        subnet = network_ops.get_random_unused_subnet()

        self.setup_exit_hub(subnet=subnet, exit_hub_name=exit_hub_name, exit_hub_password=exit_hub_password, entry_node_hostname=entry_node_hostname,
                            entry_hub_name=entry_hub_name, cascade_username=cascade_username, cascade_password=cascade_password, tap_suffix=str(proxy_port))

        mitm_ops = RoutingOps(launch_mode=self.launch_mode,
                              mitm_mode=MITMProxyMode.Web, container_ops=ContainerOps())

        mitm_data_path = os.path.join(
            self.machine_config["Stoarge"]["session_data_path"], session_data_subfolder)
        mitm_config_path = os.path.join(
            self.machine_config["Stoarge"]["session_config_path"], "mitmconfig_%s" % (session_data_subfolder))

        sys_ops.bash("rm -rf %s && mkdir -p %s" %
                     (mitm_data_path, mitm_data_path))
        sys_ops.bash("rm -rf %s && mkdir -p %s" %
                     (mitm_config_path, mitm_config_path))

        volume_mounts = [(mitm_data_path, "/host/data/"),
                         (mitm_config_path, "/host/config/")]

        mitm_ca_filename = os.path.join(mitm_config_path, "mitmproxy-ca.pem")
        mitm_ca_cert_filename = os.path.join(
            mitm_config_path, "mitmproxy-ca-cert.pem")

        try:
            with open(mitm_ca_filename, "w") as f:
                f.write(mitm_ca)

            with open(mitm_ca_cert_filename, "w") as f:
                f.write(mitm_ca_cert)
        except Exception:
            raise Exception("Custom CA files could not be written")

        internal_interface_ip = network_ops.create_address_of_subnet(
            subnet=subnet, ipv4addr_part4=1)
        internal_interface_cird = subnet.prefixlen

        if mitm_ops.launch_mitm(output_mitm_file="/host/data/session_traffic.mitm",
                                output_har_file="/host/data/session_traffic.har",
                                custom_config_dir="/host/config/",
                                volume_mounts=volume_mounts,
                                internal_interface_ip=internal_interface_ip,
                                proxy_port=proxy_port, web_port=web_port) is False:
            raise Exception("Could not launch MITM")

        if mitm_ops.route_traffic_to_mitm(interface_internal="tap_%s" % (proxy_port), internal_interface_ip=internal_interface_ip, internal_interface_cird=internal_interface_cird,
                                          interface_external=self.machine_config["Exit_Node"]["gateway_interface"], proxy_port=proxy_port) is False:
            raise Exception("Could not route traffic to MITM")

        return {"mitm_proxy_port": proxy_port, "mitm_web_port": web_port, "subnet": str(subnet)}

    def stop_dump_session_on_exit_node(self, exit_hub_name, tap_suffix, subnet_str, session_data_subfolder):

        softether_ops = SoftetherOps(
            launch_mode=self.launch_mode, container_ops=ContainerOps())

        network_ops = NetworkOps()

        softether_password = self.machine_config["Exit_Node"]["softether_password"]

        routing_ops = RoutingOps(
            launch_mode=self.launch_mode, container_ops=ContainerOps())

        subnet = ipaddress.IPv4Network(subnet_str)
        internal_interface_ip = network_ops.create_address_of_subnet(
            subnet=subnet, ipv4addr_part4=1)
        internal_interface_cird = str(subnet.prefixlen)
        remove_routing_rule_result = routing_ops.route_traffic_to_gateway(interface_internal="tap_%s" % (
            tap_suffix), interface_external=self.machine_config["Exit_Node"]["gateway_interface"], internal_interface_ip=internal_interface_ip, internal_interface_cird=internal_interface_cird, undo=True)

        containerOps = ContainerOps()
        stop_tcpdump_result = containerOps.docker(
            "stop dump_tap_%s" % (tap_suffix))

        remove_bridge_result = softether_ops.remove_bridge(
            tap_name=tap_suffix, hub=exit_hub_name, server_password=softether_password)

        delete_hub_result = softether_ops.delete_hub(
            hub=exit_hub_name, server_password=softether_password)

        self.move_data_to_storage(os.path.join(
            self.machine_config["Stoarge"]["session_data_path"], session_data_subfolder))

        if not all([remove_routing_rule_result, stop_tcpdump_result, remove_bridge_result, delete_hub_result]):
            error_messages = []
            if not remove_routing_rule_result:
                error_messages.append("Routing rules could not be removed")
            if not stop_tcpdump_result:
                error_messages.append("Tcpdump could not be stoped")
            if not remove_bridge_result:
                error_messages.append("Bridging could not be removed")
            if not delete_hub_result:
                error_messages.append("Exit hub could not be deleted")
            raise Exception("; ".join(error_messages))

        return True

    def stop_mitm_session_on_exit_node(self, exit_hub_name, mitm_proxy_port, subnet_str, session_data_subfolder):

        softether_ops = SoftetherOps(
            launch_mode=self.launch_mode, container_ops=ContainerOps())

        network_ops = NetworkOps()

        softether_password = self.machine_config["Exit_Node"]["softether_password"]

        mitm_ops = RoutingOps(launch_mode=self.launch_mode,
                              mitm_mode=MITMProxyMode.Web, container_ops=ContainerOps())

        subnet = ipaddress.IPv4Network(subnet_str)
        internal_interface_ip = network_ops.create_address_of_subnet(
            subnet=subnet, ipv4addr_part4=1)
        internal_interface_cird = str(subnet.prefixlen)
        remove_routing_rule_result = mitm_ops.route_traffic_to_mitm(interface_internal="tap_%s" % (mitm_proxy_port), internal_interface_ip=internal_interface_ip, internal_interface_cird=internal_interface_cird,
                                                                    interface_external=self.machine_config["Exit_Node"]["gateway_interface"], proxy_port=mitm_proxy_port, undo=True)

        stop_mitm_result = mitm_ops.stop_mitm(mitm_proxy_port)

        remove_bridge_result = softether_ops.remove_bridge(
            tap_name=mitm_proxy_port, hub=exit_hub_name, server_password=softether_password)

        delete_hub_result = softether_ops.delete_hub(
            hub=exit_hub_name, server_password=softether_password)

        shutil.rmtree(path=os.path.join(
            self.machine_config["Stoarge"]["session_config_path"], "mitmconfig_%s" % (session_data_subfolder)), ignore_errors=True)

        self.move_data_to_storage(os.path.join(
            self.machine_config["Stoarge"]["session_data_path"], session_data_subfolder))

        if not all([remove_routing_rule_result, stop_mitm_result, remove_bridge_result, delete_hub_result]):
            error_messages = []
            if not remove_routing_rule_result:
                error_messages.append("Routing rules could not be removed")
            if not stop_mitm_result:
                error_messages.append("MITM could not be stoped")
            if not remove_bridge_result:
                error_messages.append("Bridging could not be removed")
            if not delete_hub_result:
                error_messages.append("Exit hub could not be deleted")
            raise Exception("; ".join(error_messages))

        return True

    def stop_session_on_entry_node(self, entry_hub_name):

        softether_ops = SoftetherOps(
            launch_mode=self.launch_mode, container_ops=ContainerOps())

        softether_password = self.machine_config["Entry_Node"]["softether_password"]

        return softether_ops.delete_hub(hub=entry_hub_name, server_password=softether_password)

    def move_data_to_storage(self, session_data_path=None, in_new_thread=True):
        if session_data_path:
            if os.path.exists(session_data_path):
                if not in_new_thread:
                    shutil.move(
                        session_data_path, self.machine_config["Stoarge"]["data_storage_path"])
                else:
                    new_thread = threading.Thread(
                        target=self.move_data_to_storage, args=(session_data_path, False))
                    new_thread.setDaemon(True)
                    new_thread.start()
        pass


def coordination_function_call_handler(original_request, in_new_thread=True):
    if in_new_thread:
        thread = threading.Thread(
            target=coordination_function_call_handler, args=(original_request, False))
        thread.start()
    else:
        parameters = original_request["parameters"]

        execution_response = {"message_type": CoordinationPubSubMessageType.response_from_machine_to_coordination.name,
                              "original_request": original_request,
                              "function_returned": None, "error_message": None}

        this_machine = Machine(
            launch_mode=LaunchMode.DockerContainer, machine_config=pubsub_machine_config)

        function_to_call = getattr(this_machine, original_request["function"])

        try:
            execution_response["function_returned"] = function_to_call(
                **parameters)
        except Exception as ex:
            execution_response["error_message"] = str(ex)

        # sub_log.debug(json.dumps(execution_response))
        redis_client.publish("coordination",
                             json.dumps(execution_response))
    pass


def redis_subscription_handler(message):
    sub_log = logging.getLogger("Channel_%s" % (message["channel"]))
    # sub_log = logging.getLogger("Subscription")
    try:
        request = json.loads(message["data"])
        if CoordinationPubSubMessageType[request["message_type"]] == CoordinationPubSubMessageType.function_call_to_machine_from_coordination:
            coordination_function_call_handler(request)
    except Exception as ex:
        sub_log.debug(ex)
        sub_log.debug(message)
    pass


def new_redis_connection_thread(machine_config: {}, channel=None, logger=None):
    host = machine_config["Redis_PubSub"]["hostname"]
    password = machine_config["Redis_PubSub"]["password"]
    port = int(machine_config["Redis_PubSub"]["port"])
    db_index = int(machine_config["Redis_PubSub"]["db"])
    if not channel:
        channel = machine_config["Redis_PubSub"]["default_listening_channel"]
    global redis_client
    redis_client = redis.Redis(
        host=host, port=port, password=password, db=db_index)
    redis_pubsub = redis_client.pubsub()
    global pubsub_machine_config
    pubsub_machine_config = machine_config
    redis_pubsub.psubscribe(**{channel: redis_subscription_handler})
    thread = redis_pubsub.run_in_thread(sleep_time=0.01)
    if logger:
        logger.info(f"Subscrbied to '{channel}' channel on Redis ...")
    return thread


def listen_to_pubsub(machine_config: {}, channel=None):
    thread = None
    logger = logging.getLogger("PubSubLog")
    redis_server_info = "%s:%s" % (machine_config["Redis_PubSub"]["hostname"], machine_config["Redis_PubSub"]["port"])
    while True:
        try:
            if not thread:
                logger.info(f"Connecting to Redis {redis_server_info} ...")
                thread = new_redis_connection_thread(machine_config=machine_config, channel=channel, logger=logger)
            elif not thread.is_alive():
                logger.info(f"Disconnected from {redis_server_info} ...")
                thread = None
                gc.collect()
        except redis.exceptions.ConnectionError:
                logger.info(f"Could not connect to Redis {redis_server_info} ...")
                thread = None
                gc.collect()
        time.sleep(int(machine_config["Redis_PubSub"]["connection_watchdog_interval_sec"]))
    pass


def main():
    arg_praser = argparse.ArgumentParser(
        description="AppTraffic agent running on an entry node or exit node")
    arg_praser.add_argument("--start-entry-node", help="start and configure a Softether container to serve as an entry node",
                            dest="start_entry_node", action="store_true", required=False)
    arg_praser.add_argument("--start-exit-node", help="start and configure a Softether container to serve as an exit node",
                            dest="start_exit_node", action="store_true", required=False)
    arg_praser.add_argument("--stop-entry-node", help="stop the entry node container",
                            dest="stop_entry_node", action="store_true", required=False)
    arg_praser.add_argument("--stop-exit-node", help="stop the exit node container",
                            dest="stop_exit_node", action="store_true", required=False)
    arg_praser.add_argument("--listen", help="listen to a channel of the Redis pubsub service",
                            dest="listen_to_pubsub", action="store_true", required=False)
    arg_praser.add_argument("--channel", metavar='channel_name', help="the channel to which this application listens",
                            dest="redis_channel", default=None, required=False)
    arg_praser.add_argument("--config", metavar='filename', help="the path of the config json file (if not specified, by default: machine_config.ini)",
                            nargs="?", default="./machine_config.ini", required=False)

    args = arg_praser.parse_args()

    machine_config = configparser.ConfigParser()
    machine_config.read(args.config)

    if args.start_entry_node:
        machine = Machine(launch_mode=LaunchMode.DockerContainer,
                          machine_config=machine_config)
        machine.start_entry_node()
    elif args.start_exit_node:
        machine = Machine(launch_mode=LaunchMode.DockerContainer,
                          machine_config=machine_config)
        machine.start_exit_node()
    elif args.stop_entry_node:
        machine = Machine(launch_mode=LaunchMode.DockerContainer,
                          machine_config=machine_config)
        machine.stop_entry_node()
    elif args.stop_exit_node:
        machine = Machine(launch_mode=LaunchMode.DockerContainer,
                          machine_config=machine_config)
        machine.stop_exit_node()
    elif args.listen_to_pubsub:
        listen_to_pubsub(
            channel=args.redis_channel, machine_config=machine_config)
    pass


if __name__ == '__main__':
    main()
