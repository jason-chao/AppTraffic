#!/usr/bin/env python3

import json
from bson.json_util import dumps
import re
from enum import Enum, auto
import re
import pymongo
import bcrypt
import base64
import configparser
import os
import subprocess
import redis
import datetime
import string
import secrets
import argparse
import pprint
import hashlib
import yaml
import enum
import threading
import uuid
import time
import gc


from validator_collection import checkers

from apptraffic import *


logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)


class SessionStatus(enum.Enum):
    creating = enum.auto()
    recording = enum.auto()
    ending = enum.auto()
    ended = enum.auto()
    creating_entry_hub = enum.auto()
    creating_exit_hub = enum.auto()
    created_entry_hub = enum.auto()
    # since recording starts after the exit hub is created, created_exit_hub may not be necessnary
    # created_exit_hub = enum.auto()
    error_creating_entry_hub = enum.auto()
    error_creating_exit_hub = enum.auto()


class CoordinationPubSubMessageType(enum.Enum):
    function_call_to_machine_from_coordination = enum.auto()
    response_from_machine_to_coordination = enum.auto()


class CoordinationValidator:

    def is_valid_email(self, input):
        return checkers.is_email(input)

    def is_valid_password(self, input):
        if not checkers.is_string(input):
            return False
        if not checkers.has_length(input, minimum=8):
            return False
        if not (re.search("[a-z]", input) and re.search("[A-Z]", input) and re.search("[0-9]", input)):
            return False
        return True

    def is_valid_username(self, input):
        if not checkers.is_string(input):
            return False
        if not checkers.has_length(input, minimum=6):
            return False
        if not re.search("[a-z]", input):
            return False
        return True


class CoordinationUtility():
    def __int__(self):
        pass

    def generate_vpn_hub_password(self):
        return secrets.token_urlsafe(16)

    def hash_password(self, plaintext_password):
        hashed_password = bcrypt.hashpw(
            plaintext_password.encode("utf-8"), bcrypt.gensalt(14))
        return base64.b64encode(hashed_password)

    def check_password(self, plaintext_password, hashed_password):
        return bcrypt.checkpw(plaintext_password.encode("utf-8"), base64.b64decode(hashed_password))


class Coordination():

    def __init__(self, db_client: pymongo.MongoClient, db_name: str, redis_client: redis.Redis, service_name="default"):
        self.log = logging.getLogger("CoordinationLog")
        self.db_client = db_client
        self.db_name = db_name
        self.db = db_client[self.db_name]
        self.validator = CoordinationValidator()
        self.redis_client = redis_client
        self.service_name = service_name
        self.accepted_intercept_modes = ["metadata", "raw", "decrypted"]
        self.utility = CoordinationUtility()
        pass

    def db_init(self):
        research_user_collection = self.db["research_user"]
        research_user_collection.create_index(
            [("username", pymongo.DESCENDING)], unique=True)
        research_user_collection.create_index(
            [("email", pymongo.DESCENDING)], unique=True)
        pass

    def generate_CA(self, cn_suffix="", keep_generated_pem_files=False):
        # it relies on the scripts in the ca-certificates to generate the required CA certificates
        ca_utility_path = "./ca-certificates/"
        if not ca_utility_path.startswith(r"/"):
            ca_utility_path = os.path.normpath(os.path.join(
                os.getcwd(), ca_utility_path))
        subprocess.run(os.path.join(ca_utility_path,
                                    "clear_saved_ca.sh"), cwd=ca_utility_path)
        if subprocess.run([os.path.join(ca_utility_path, "generate_ca.sh"), cn_suffix], cwd=ca_utility_path).returncode != 0:
            return None
        ca_file = open(os.path.join(ca_utility_path, "ca.pem"), "r")
        ca_cert_file = open(os.path.join(ca_utility_path, "ca-cert.pem"), "r")
        ca = {}
        ca["ca"] = ca_file.read()
        ca["ca-cert"] = ca_cert_file.read()
        ca_file.close()
        ca_cert_file.close()
        if keep_generated_pem_files is False:
            subprocess.run(os.path.join(ca_utility_path,
                                        "clear_saved_ca.sh"), cwd=ca_utility_path)
        return ca

    def edit_user(self, username, user_doc):
        username = username.lower().strip()
        research_user_collection = self.db["research_user"]
        # changing of password is not supported by this function
        if "password" in user_doc.keys():
            user_doc.pop("password")
        result = research_user_collection.update_one(
            filter={"username": username}, update={"$set": user_doc})
        return result.modified_count > 0

    def check_user_password(self, username_or_email, password):
        research_user_collection = self.db["research_user"]
        user_doc = research_user_collection.find_one(
            {"$or": [{"username": username_or_email}, {"email": username_or_email}]}, {"password": 1})
        return self.utility.check_password(password, user_doc["password"])

    def change_user_password(self, username, old_password, new_password):
        new_password = new_password.strip()
        if self.check_user_password(username, old_password):
            research_user_collection = self.db["research_user"]
            research_user_collection.update_one(filter={"username": username}, update={
                                                "$set": {"password": self.utility.hash_password(new_password)}})
            return self.check_user_password(username, new_password)
        return False

    def get_user(self, username_or_email, including_inactive=False):
        research_user_collection = self.db["research_user"]
        user_doc = research_user_collection.find_one(
            {"$or": [{"username": username_or_email}, {"email": username_or_email}]}, {"password": 0})
        # self.log.debug(dumps(user_doc))
        if not including_inactive:
            if "suspended" in user_doc:
                raise Exception("The user account is not active.")
        return user_doc

    def create_user(self, username, password, email, category="basic"):
        username = username.lower().strip()
        password = password.strip()
        email = email.lower().strip()

        if not (self.validator.is_valid_email(email) and self.validator.is_valid_password(password) and self.validator.is_valid_username(username)):
            raise Exception("Username, password or email is invalid")

        research_user_collection = self.db["research_user"]

        if research_user_collection.find({"$or": [{"email": email}, {"username": username}]}).count() > 0:
            raise Exception("Username or email exists")

        ca = self.generate_CA(cn_suffix=f"{self.service_name}_{username}")

        new_user = {"email": email, "username": username, "password": self.utility.hash_password(password),
                    "activated": False, "category": category, "privileges": ["decrypted", "raw", "metadata"], "certificates": ca,
                    "vpn_users": [{"username": "vpn", "password": "default"}]
                    }

        self.log.debug(research_user_collection.insert_one(
            new_user).inserted_id)

        return True

    def generate_user_device_config_vpn_connection_info(self, username, vpn_user, machine):
        vpn_connection = {}
        vpn_connection["name"] = "AppTraffic %s (%s)" % (
            self.service_name, machine["name"])
        vpn_connection["entry_node_id"] = machine["_id"]
        vpn_connection["hostname"] = machine["public_hostname"]
        vpn_connection["username"] = "%s@%s" % (
            vpn_user["username"], "_".join([username, vpn_user["username"]]) + "_entry")
        vpn_connection["password"] = vpn_user["password"]
        vpn_connection["pre_shared_key_ascii"] = machine["softether_vpn_l2tp_psk"]
        vpn_connection["pre_shared_key_base64"] = base64.b64encode(
            machine["softether_vpn_l2tp_psk"].encode(encoding="ascii")).decode()
        return vpn_connection

    def generate_user_device_config_ios_profile(self, user, vpn_user):
        config_profile = {"profile_uuid": str(uuid.uuid4()).upper(),
                          "profile_name": "AppTraffic %s %s %s" % (self.service_name, user["username"], vpn_user["username"]),
                          "profile_identifier": "%s.%s.apptraffic" % (vpn_user["username"], user["username"]),
                          "vpn_connections": []}
        return config_profile

    def update_user_device_config_ios_profile(self, username, vpn_username=None):
        user = self.get_user(username)
        vpn_user = self.get_user_vpnuser(username, vpn_username)
        active_entry_nodes = self.get_machines(filter={"type": "entry"})
        profile_key = "ios_mobileconfig_%s" % (vpn_user["username"])

        if "device_config_profiles" not in user:
            device_config = {}
            device_config[profile_key] = self.generate_user_device_config_ios_profile(
                user, vpn_user)
            for machine in active_entry_nodes:
                vpn_connection = self.generate_user_device_config_vpn_connection_info(
                    username, vpn_user, machine)
                vpn_connection["connection_uuid"] = str(uuid.uuid4()).upper()
                device_config[profile_key]["vpn_connections"].append(
                    vpn_connection)
        else:
            device_config = user["device_config_profiles"]
            if profile_key in device_config:
                exit_node_uuid_map = dict(list(
                    [(c["entry_node_id"], c["connection_uuid"]) for c in device_config[profile_key]["vpn_connections"]]))
                device_config[profile_key]["vpn_connections"] = []
                for machine in active_entry_nodes:
                    vpn_connection = self.generate_user_device_config_vpn_connection_info(
                        username, vpn_user, machine)
                    if vpn_connection["entry_node_id"] in exit_node_uuid_map.keys():
                        vpn_connection["connection_uuid"] = exit_node_uuid_map[vpn_connection["entry_node_id"]]
                    else:
                        vpn_connection["connection_uuid"] = str(
                            uuid.uuid4()).upper()
                    device_config[profile_key]["vpn_connections"].append(
                        vpn_connection)

        device_config[profile_key]["xml"] = self.generate_ios_mobileconfig_xml(
            device_config[profile_key])

        self.edit_user(username, {"device_config_profiles": device_config})
        return profile_key

    def generate_ios_mobileconfig_xml(self, ios_mobileconfig):
        template_path = "./templates/"
        mobileconfig_template = open(os.path.join(
            template_path, "ios-mobileconfig.xml"), "r").read()
        mobileconfig_vpn_template = open(os.path.join(
            template_path, "ios-mobileconfig-vpn.xml"), "r").read()
        config_xml = mobileconfig_template
        config_xml = config_xml.replace(
            "<!--field_profile_payload_uuid-->", ios_mobileconfig["profile_uuid"])
        config_xml = config_xml.replace(
            "<!--field_profile_name-->", ios_mobileconfig["profile_name"])
        config_xml = config_xml.replace(
            "<!--field_profile_identifier-->", ios_mobileconfig["profile_identifier"])
        vpn_connection_xml_list = []
        for vpn_config in ios_mobileconfig["vpn_connections"]:
            vpn_connection_xml = mobileconfig_vpn_template
            vpn_connection_xml = vpn_connection_xml.replace(
                "<!--field_SharedSecret_base64-->", vpn_config["pre_shared_key_base64"])
            vpn_connection_xml = vpn_connection_xml.replace(
                "<!--field_vpn_username-->", vpn_config["username"])
            vpn_connection_xml = vpn_connection_xml.replace(
                "<!--field_vpn_password-->", vpn_config["password"])
            vpn_connection_xml = vpn_connection_xml.replace(
                "<!--field_vpn_entrypoint_hostname-->", vpn_config["hostname"])
            vpn_connection_xml = vpn_connection_xml.replace(
                "<!--field_vpn_payload_uuid-->", vpn_config["connection_uuid"])
            vpn_connection_xml = vpn_connection_xml.replace(
                "<!--field_vpn_connection_name-->", vpn_config["name"])
            vpn_connection_xml_list.append(vpn_connection_xml)
        config_xml = config_xml.replace(
            "<!--dict_vpn_config-->", "\n".join(vpn_connection_xml_list))
        return config_xml

    def get_user_ios_mobileconfig(self, username, vpn_username=None):
        profile_key = self.update_user_device_config_ios_profile(
            username, vpn_username)
        user = self.get_user(username)
        return user["device_config_profiles"][profile_key]["xml"]

    def load_machines(self, machines: []):
        machine_collection = self.db["machine"]
        machine_collection.delete_many({})
        result = machine_collection.insert_many(machines)
        return result.acknowledged

    def get_machines(self, filter={}, including_inactive=False):
        if not including_inactive:
            filter["active"] = True
        machine_collection = self.db["machine"]
        return list(machine_collection.find(filter))

    def get_session(self, session_id, with_log=False, including_removed=False):
        session_collection = self.db["session"]
        query = {"_id": session_id}
        if not including_removed:
            query["removed"] = {"$exists": False}
        session = session_collection.find_one(
            query, None if with_log else {"log": 0})
        # self.log.debug(dumps(session))
        return session

    def update_session(self, session_id, doc_update):
        session_collection = self.db["session"]
        result = session_collection.update_one(
            filter={"_id": session_id}, update={"$set": doc_update})
        return result.modified_count > 0

    def write_session_log_entry(self, session_id, log_entry_text):
        session_collection = self.db["session"]
        log_entry = {
            "datetime": datetime.datetime.utcnow(),
            "entry_text": log_entry_text
        }
        return session_collection.update_one(filter={"_id": session_id}, update={"$push": {"log": log_entry}})

    def mark_session_as_removed(self, session_id):
        return self.update_session(session_id, {"removed": datetime.datetime.utcnow()})

    def get_user_vpnuser(self, username, vpn_username=None):
        user = self.get_user(username)
        vpn_user_query = [u for u in user["vpn_users"]
                          if u["username"] == vpn_username]

        if len(vpn_user_query) > 0:
            vpn_user = vpn_user_query[0]
        else:
            vpn_user = user["vpn_users"][0]

        return vpn_user

    def get_user_active_sessions(self, username):
        user = self.get_user(username)
        session_collection = self.db["session"]
        active_sessions = session_collection.find({"$and": [{"username": user["username"]},
                                                            {"removed": {
                                                                "$exists": False}},
                                                            {"status": {"$in": [SessionStatus.creating.name,
                                                                                SessionStatus.recording.name,
                                                                                SessionStatus.creating_entry_hub.name,
                                                                                SessionStatus.creating_exit_hub.name,
                                                                                SessionStatus.created_entry_hub.name,
                                                                                ]}}
                                                            ]},
                                                  {"_id": 1, "status": 1, "resources.entry_node._id": 1, "resources.exit_node._id": 1, "intercept_mode": 1, "vpn_entry_hub": 1, "vpn_exit_hub": 1, "created": 1})
        return list(active_sessions)

    def new_session(self, username, entry_node_machine_id, exit_node_machine_id, intercept_mode, vpn_username=None, session_name=None):

        if intercept_mode not in self.accepted_intercept_modes:
            raise Exception("Invalid intercept mode")

        user_active_sessions = self.get_user_active_sessions(username)
        if len(user_active_sessions) > 0:
            raise Exception(
                "The user has an active recording session.  End all active sessions before starting a new one.")

        session_collection = self.db["session"]

        user = self.get_user(username)

        if intercept_mode not in user["privileges"]:
            raise Exception(
                "The user does not the permission to record traffic in '%s' mode" % (intercept_mode))

        entry_node_machine = self.get_machines(
            {"_id": entry_node_machine_id})[0]
        exit_node_machine = self.get_machines({"_id": exit_node_machine_id})[0]

        vpn_user = self.get_user_vpnuser(username, vpn_username)

        session_created_time = datetime.datetime.utcnow()
        #session_name = session_start_time.strftime("%Y%M%d%H%m%S") + "_" + vpn_user["username"]
        # entry_hub_name =

        vpn_hub_name = "_".join([username, vpn_user["username"]])
        vpn_hub_password = CoordinationUtility().generate_vpn_hub_password()
        session_id = "_".join(
            [session_created_time.strftime("%Y%m%d%H%M%S"), vpn_hub_name])

        new_session = {
            "_id": session_id,
            "status": SessionStatus.creating.name,
            "username": username,
            "name": session_name,
            "vpn_username": vpn_user["username"],
            "vpn_password": vpn_user["password"],
            "created": session_created_time,
            "intercept_mode": intercept_mode,
            "mitm-ca": user["certificates"] if intercept_mode == "decrypted" else None,
            "vpn_psk": entry_node_machine["softether_vpn_l2tp_psk"],
            "vpn_entry_hub": vpn_hub_name + "_entry",
            "vpn_exit_hub": vpn_hub_name + "_exit",
            "vpn_entry_hub_password": vpn_hub_password,
            "vpn_cascade_user": "cascade_user",
            "vpn_cascade_user_password": vpn_hub_password,
            "vpn_exit_hub_password": vpn_hub_password,
            "log": [],
            "resources": {"entry_node": entry_node_machine, "exit_node": exit_node_machine}
        }

        # in decryption mode, the proxy port will be used as the suffix for easy identification
        # in metadata and raw modes, a tap suffix needs to be generated
        if intercept_mode in ["metadata", "raw"]:
            new_session["tap_suffix"] = hashlib.sha256(
                session_id.encode("utf-8")).hexdigest()[:8]

        session_insertion_result = session_collection.insert_one(new_session)

        if session_insertion_result.inserted_id != session_id:
            raise Exception("New session could not be written to the database")

        self.write_session_log_entry(session_id, "Session record created")

        return session_id

    def start_session_on_entry_node(self, session_id):

        session = self.get_session(session_id)

        if SessionStatus[session['status']] != SessionStatus.creating:
            self.write_session_log_entry(
                session_id, "Declined to start a session on entry node because of incorrect session status")
            return

        request_to_entry_node = {"message_type": CoordinationPubSubMessageType.function_call_to_machine_from_coordination.name,
                                 "function": "new_session_on_entry_node",
                                 "session_id": session["_id"],
                                 "parameters": {
                                     "entry_hub_name": session["vpn_entry_hub"],
                                     "entry_hub_password": session["vpn_entry_hub_password"],
                                     "vpn_username": session["vpn_username"],
                                     "vpn_password": session["vpn_password"],
                                     "cascade_username": session["vpn_cascade_user"],
                                     "cascade_password": session["vpn_cascade_user_password"]
                                 }
                                 }

        self.update_session(
            session_id, {"status": SessionStatus.creating_entry_hub.name})
        self.write_session_log_entry(session_id, "Creating the entry hub")

        self.redis_client.publish(
            channel=session["resources"]["entry_node"]["_id"], message=json.dumps(request_to_entry_node))

    def end_session(self, session_id):

        session = self.get_session(session_id)

        if SessionStatus[session['status']] not in [SessionStatus.recording, SessionStatus.created_entry_hub, SessionStatus.creating_exit_hub]:
            self.write_session_log_entry(
                session_id, "Declined to stop the session because of incorrect session status")
            return

        request_to_entry_node = {
            "message_type": CoordinationPubSubMessageType.function_call_to_machine_from_coordination.name,
            "function": "stop_session_on_entry_node",
            "session_id": session["_id"],
            "parameters": {
                "entry_hub_name": session["vpn_entry_hub"]
            }
        }

        request_to_exit_node = None

        parameters_for_exit_node_base = {
            "exit_hub_name": session["vpn_exit_hub"],
            "subnet_str": session["subnet"],
            "session_data_subfolder": session["_id"]
        }

        if session["intercept_mode"] == "decrypted":
            request_to_exit_node = {
                "message_type": CoordinationPubSubMessageType.function_call_to_machine_from_coordination.name,
                "function": "stop_mitm_session_on_exit_node",
                "session_id": session["_id"],
                "parameters": {
                    ** parameters_for_exit_node_base,
                    "mitm_proxy_port": session["mitm_proxy_port"]
                    # "exit_hub_name": session["vpn_exit_hub"],
                    # "subnet_str": session["subnet"],
                    # "session_data_subfolder": session["_id"]
                }
            }
        elif session["intercept_mode"] == "raw" or session["intercept_mode"] == "metadata":
            request_to_exit_node = {
                "message_type": CoordinationPubSubMessageType.function_call_to_machine_from_coordination.name,
                "function": "stop_dump_session_on_exit_node",
                "session_id": session["_id"],
                "parameters": {
                    ** parameters_for_exit_node_base,
                    "tap_suffix": session["tap_suffix"],
                    # "exit_hub_name": session["vpn_exit_hub"],
                    # "subnet_str": session["subnet"],
                    # "session_data_subfolder": session["_id"]
                }
            }

        self.log.debug(dumps(request_to_exit_node))

        self.update_session(session_id, {"status": SessionStatus.ending.name})
        self.write_session_log_entry(
            session_id, "Stopping the entry and exit hubs")

        self.redis_client.publish(
            channel=session["resources"]["entry_node"]["_id"], message=json.dumps(request_to_entry_node))

        if request_to_exit_node is not None:
            self.redis_client.publish(
                channel=session["resources"]["exit_node"]["_id"], message=json.dumps(request_to_exit_node))

        pass

    def start_session_on_exit_node(self, session_id):

        session = self.get_session(session_id)

        if SessionStatus[session['status']] != SessionStatus.created_entry_hub:
            self.write_session_log_entry(
                session_id, "Declined to start a session on exit node because of incorrect session status")

        request_to_exit_node = {"message_type": CoordinationPubSubMessageType.function_call_to_machine_from_coordination.name,
                                "function": None,
                                "session_id": session["_id"],
                                "parameters": {
                                    "exit_hub_name": session["vpn_exit_hub"],
                                    "exit_hub_password": session["vpn_exit_hub_password"],
                                    "entry_node_hostname": session["resources"]["entry_node"]["hostname"],
                                    "entry_hub_name": session["vpn_entry_hub"],
                                    "cascade_username": session["vpn_cascade_user"],
                                    "cascade_password": session["vpn_cascade_user_password"],
                                    "session_data_subfolder": session["_id"]
                                }
                                }

        if session["intercept_mode"] == "decrypted":
            request_to_exit_node["function"] = "new_mitm_session_on_exit_node"
            request_to_exit_node["parameters"]["mitm_ca"] = session["mitm-ca"]["ca"]
            request_to_exit_node["parameters"]["mitm_ca_cert"] = session["mitm-ca"]["ca-cert"]
        elif session["intercept_mode"] == "raw" or session["intercept_mode"] == "metadata":
            request_to_exit_node["function"] = "new_dump_session_on_exit_node"
            request_to_exit_node["parameters"]["intercept_mode"] = session["intercept_mode"]
            request_to_exit_node["parameters"]["tap_suffix"] = session["tap_suffix"]
            pass

        if request_to_exit_node["function"] is not None:

            self.update_session(
                session_id, {"status": SessionStatus.creating_exit_hub.name})
            self.write_session_log_entry(
                session_id, "Creating the exit hub and starting the traffic capturer")

            self.redis_client.publish(
                channel=session["resources"]["exit_node"]["_id"], message=json.dumps(request_to_exit_node))
        pass

    def on_session_started_on_entry_node(self, session_id, success=False, error_message=None):

        if success:
            self.write_session_log_entry(session_id, "Entry hub is created")
            self.update_session(session_id, {
                                "status": SessionStatus.created_entry_hub.name, "resources.entry_node.created": datetime.datetime.utcnow()})
            self.start_session_on_exit_node(session_id)
        else:
            self.update_session(
                session_id, {"status": SessionStatus.error_creating_entry_hub.name})
            self.write_session_log_entry(session_id, "Failed to create an entry hub%s" % (
                " (" + error_message + ")" if error_message else ""))
        pass

    def on_session_started_on_exit_node(self, session_id, new_attributes_for_session={}, error_message=None):

        hub_created = False

        if new_attributes_for_session:
            session = self.get_session(session_id)

            if session["intercept_mode"] == "decrypted":
                if "subnet" in new_attributes_for_session and "mitm_proxy_port" in new_attributes_for_session and "mitm_web_port" in new_attributes_for_session:
                    hub_created = True
                    self.update_session(
                        session_id, new_attributes_for_session)
            else:
                if error_message is None and "subnet" in new_attributes_for_session:
                    hub_created = True
                    self.update_session(
                        session_id, new_attributes_for_session)

        if hub_created:
            self.write_session_log_entry(session_id, "Recording traffic")
            self.update_session(session_id, {
                                "status": SessionStatus.recording.name, "resources.exit_node.created": datetime.datetime.utcnow()})
        else:
            self.write_session_log_entry(session_id, "Exit hub is not created or is not properly created%s" % (
                " (" + error_message + ")" if error_message else ""))
            self.update_session(
                session_id, {"status": SessionStatus.error_creating_exit_hub.name})
        pass

    def on_session_stopped_on_node(self, session_id, node_type, success, error_message=None):

        if node_type == "entry_node":
            if success:
                self.write_session_log_entry(
                    session_id, "Entry hub is removed")
                self.update_session(
                    session_id, {"resources.entry_node.removed": datetime.datetime.utcnow()})
            else:
                self.write_session_log_entry(
                    session_id, "Entry hub could not be removed%s" % (
                        " (" + error_message + ")" if error_message else ""))
        elif node_type == "exit_node":
            if success:
                self.write_session_log_entry(session_id, "Exit hub is removed")
                self.update_session(
                    session_id, {"resources.exit_node.removed": datetime.datetime.utcnow()})
            else:
                self.write_session_log_entry(
                    session_id, "Exit hub could not be removed%s" % (
                        " (" + error_message + ")" if error_message else ""))

        session = self.get_session(session_id)

        if "removed" in session["resources"]["entry_node"] and "removed" in session["resources"]["exit_node"]:
            self.update_session(
                session_id, {"status": SessionStatus.ended.name, "ended": datetime.datetime.utcnow()})
            self.write_session_log_entry(
                session_id, "Session ended")

        pass


def machine_reply_handler(message_obj, in_new_thread=True):
    if in_new_thread:
        thread = threading.Thread(
            target=machine_reply_handler, args=(message_obj, False))
        thread.start()
    else:

        from_function = message_obj["original_request"]["function"]
        session_id = message_obj["original_request"]["session_id"]
        function_returned = message_obj["function_returned"]
        error_message = message_obj["error_message"]

        if from_function == "new_session_on_entry_node":
            coordination.on_session_started_on_entry_node(
                session_id=session_id, success=function_returned, error_message=error_message)
        elif from_function in ["new_mitm_session_on_exit_node", "new_dump_session_on_exit_node"]:
            coordination.on_session_started_on_exit_node(
                session_id=session_id, new_attributes_for_session=function_returned, error_message=error_message)
        elif from_function in ["stop_mitm_session_on_exit_node", "stop_dump_session_on_exit_node", "stop_session_on_entry_node"]:
            node_type = None
            if from_function.endswith("on_entry_node"):
                node_type = "entry_node"
            elif from_function.endswith("on_exit_node"):
                node_type = "exit_node"
            if node_type:
                coordination.on_session_stopped_on_node(
                    session_id=session_id, node_type=node_type, success=function_returned, error_message=error_message)
            pass
    pass


def redis_subscription_handler(message):
    sub_log = logging.getLogger("Channel_%s" % (message["channel"]))
    sub_log.debug(message)

    pubsub_message = json.loads(message["data"])
    message_type = CoordinationPubSubMessageType[pubsub_message["message_type"]]

    if message_type == CoordinationPubSubMessageType.response_from_machine_to_coordination:
        machine_reply_handler(pubsub_message)

    pass


def new_redis_connection_thread(config: {}, logger=None):
    global coordination
    global redis_client
    global mdb_client

    mdb_client = pymongo.MongoClient(
        config["Coordination"]["mongodb_connection_string"])
    redis_client = redis.Redis(host=config["Redis_PubSub"]["hostname"],
                               port=int(
        config["Redis_PubSub"]["port"]),
        password=config["Redis_PubSub"]["password"],
        db=int(config["Redis_PubSub"]["db"]))
    db_name = config["Coordination"]["mongodb_dbname"]

    coordination = Coordination(
        db_client=mdb_client, db_name=db_name, redis_client=redis_client)

    channel = config["Redis_PubSub"]["default_listening_channel"]
    redis_pubsub = redis_client.pubsub()
    redis_pubsub.psubscribe(**{channel: redis_subscription_handler})
    thread = redis_pubsub.run_in_thread(sleep_time=0.01)
    if logger:
        logger.info(f"Subscribed to '{channel}' channel on Redis ...")
    return thread

def listen_to_pubsub(config: {}):
    thread = None
    logger = logging.getLogger("PubSubLog")
    redis_server_info = "%s:%s" % (config["Redis_PubSub"]["hostname"], config["Redis_PubSub"]["port"])
    while True:
        try:
            if not thread:
                logger.info(f"Connecting to Redis {redis_server_info} ...")
                thread = new_redis_connection_thread(config=config, logger=logger)
            elif not thread.is_alive():
                logger.info(f"Disconnected from {redis_server_info} ...")
                thread = None
                gc.collect()
        except redis.exceptions.ConnectionError:
                logger.info(f"Could not connect to Redis {redis_server_info} ...")
                thread = None
                gc.collect()
        time.sleep(int(config["Redis_PubSub"]["connection_watchdog_interval_sec"]))
    pass

def run_commands(commands: [], config: {}, stop_on_error=True):
    mdb_client = pymongo.MongoClient(
        config["Coordination"]["mongodb_connection_string"])
    redis_client = redis.Redis(host=config["Redis_PubSub"]["hostname"],
                               port=int(
        config["Redis_PubSub"]["port"]),
        password=config["Redis_PubSub"]["password"],
        db=int(config["Redis_PubSub"]["db"]))
    db_name = config["Coordination"]["mongodb_dbname"]

    coordination = Coordination(
        db_client=mdb_client, db_name=db_name, redis_client=redis_client)

    results = []
    allowed_functions = ["db_init", "create_user", "get_user", "load_machines", "get_machines",
                         "get_session", "update_session", "new_session", "end_session", "start_session_on_entry_node"]
    for c in commands:
        if c["function"] not in allowed_functions:
            continue
        function_to_call = getattr(coordination, c["function"])
        result = {"original_request": c,
                  "function_returned": None, "error_message": None}
        try:
            parameters = c["parameters"]
            result["function_returned"] = function_to_call(**parameters)
        except Exception as ex:
            result["error_message"] = str(ex)
        results.append(result)
        if stop_on_error is True and result["error_message"] is not None:
            break

    return results


def main():

    arg_praser = argparse.ArgumentParser(description="AppTraffic coordinator")
    arg_praser.add_argument("--listen", help="listen to the coordination redis channel",
                            default=False, action="store_true", required=False)
    arg_praser.add_argument("--comm-file", metavar="filename", help="execute the commands stored in a json or yaml file (default: coordination_commands.json)",
                            dest="command_filename", nargs="?", const="./coordination_commands.json", default=None, required=False)
    arg_praser.add_argument("--comm", metavar="command", help="execute the command or a list of commands formatted in json",
                            dest="command", nargs="?", default=None, required=False)
    arg_praser.add_argument("--config", metavar='filename', help="the path of the config json file (default: coordination_config.ini)",
                            nargs="?", default="./coordination_config.ini", required=False)

    args = arg_praser.parse_args()

    coordination_config = configparser.ConfigParser()
    coordination_config.read(args.config)

    if args.listen:
        listen_to_pubsub(coordination_config)
    elif args.command_filename or args.command:
        commands = None
        if args.command_filename:
            try:
                with open(args.command_filename, "r") as command_file:
                    if args.command_filename.lower().endswith(".json"):
                        commands = json.load(command_file)
                    elif args.command_filename.lower().endswith(".yaml"):
                        commands = yaml.safe_load(command_file)
            except:
                pass
        elif args.command:
            commands = args.command

        if commands:
            # by default, the run_commands function takes an array of commands as input
            # there is only a single command in the argument or in the file, it must be put in an array
            if not isinstance(commands, list):
                commands = [commands]
            results = run_commands(
                commands=commands, config=coordination_config)
            pp = pprint.PrettyPrinter(depth=6)
            pp.pprint(results)
        else:
            print("The command or the command file is invalid.")
    pass


if __name__ == '__main__':
    main()
