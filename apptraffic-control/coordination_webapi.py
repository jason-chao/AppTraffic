from flask import Flask, session, request, jsonify, Response, send_from_directory
from flask_cors import CORS

from coordination import Coordination, CoordinationValidator, SessionStatus
from analysis import Analysis_Dask, Analysis
import configparser
import pymongo
import redis
import datetime
import dateutil.parser
import base64
import jwt
import json
import os
import socket
from functools import wraps
from cryptography.fernet import Fernet


app = Flask(__name__)
CORS(app)

app.coordination_config = configparser.ConfigParser()
app.coordination_config.read("./coordination_config.ini")
app.mdb_client = pymongo.MongoClient(
    app.coordination_config["Coordination"]["mongodb_connection_string"])
app.redis_client = redis.Redis(host=app.coordination_config["Redis_PubSub"]["hostname"],
                               port=int(
    app.coordination_config["Redis_PubSub"]["port"]),
    password=app.coordination_config["Redis_PubSub"]["password"],
    db=int(app.coordination_config["Redis_PubSub"]["db"]))
app.db_name = app.coordination_config["Coordination"]["mongodb_dbname"]
app.apptraffic_service_name = app.coordination_config["Coordination"]["apptraffic_service_name"]

app.coordination = Coordination(
    db_client=app.mdb_client, db_name=app.db_name, redis_client=app.redis_client, service_name=app.apptraffic_service_name)


# the way to generate a new key - import os; import base64; print(base64.b64encode(os.urandom(32)))
# for details, see https://geekflare.com/securing-flask-api-with-jwt/
app.secret_key = base64.b64decode(
    app.coordination_config["WebAPI"]["web_session_secret"])


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"]
            token = token.replace("Bearer ", "")
        if not token:
            return jsonify({"errorMessage": "A valid user token is not present", "returned": None})
        try:
            jwt_payload = jwt.decode(token, app.secret_key)
            loggedin = dateutil.parser.parse(jwt_payload["loggedin"])
            expiry = dateutil.parser.parse(jwt_payload["expiry"])
            current_username = jwt_payload["username"]
            time_now = datetime.datetime.utcnow()
            if loggedin > time_now or time_now > expiry:
                return jsonify({"errorMessage": "The user token has expired", "returned": None})
        except Exception as ex:
            print(ex)
            return jsonify({"errorMessage": "The user token is invalid", "returned": None})
        return f(current_username, *args, **kwargs)
    return decorator


def get_response_model():
    return {"returned": None, "errorMessage": None}


def symmetrically_encrypt(plaintext):
    cipher = Fernet(base64.b64encode(app.secret_key))
    return cipher.encrypt(json.dumps(plaintext).encode()).decode()


def symmetrically_decrypt(ciphertext):
    decipher = Fernet(base64.b64encode(app.secret_key))
    return json.loads(decipher.decrypt(ciphertext.encode()).decode())


def user_has_access_to_session(user, session):
    if user["username"] == session["username"]:
        return True
    if "admin" in user["privileges"]:
        return True
    return False


def is_user_an_admin(user):
    return "admin" in user["privileges"]    


@app.route("/", methods=["GET"])
def index():
    session["username"] = datetime.datetime.utcnow().isoformat()
    return datetime.datetime.utcnow().isoformat()


@app.route("/node/all", methods=["GET"])
@token_required
def get_nodes(username):
    result = get_response_model()
    result["returned"] = {}
    try:
        result["returned"] = { "exit": [], "entry": [] }
        exit_nodes = app.coordination.get_machines(filter={"type": "exit" })
        result["returned"]["exit"] = list([{"nodeName": f"{node['name']}, {node['location']}", "nodeId": node["_id"]} for node in exit_nodes])
        entry_nodes = app.coordination.get_machines(filter={"type": "entry" })
        result["returned"]["entry"] = list([{"nodeName": f"{node['name']}, {node['location']}", "nodeId": node["_id"]} for node in entry_nodes])
    except:
        result["errorMessage"] = "Could not read the data about nodes"
    return jsonify(result)


@app.route("/user/signup", methods=["POST"])
def signup():
    result = get_response_model()
    try:
        signup_form = request.get_json()
        signup_form["email"] = signup_form["email"].lower().strip()
        signup_form["username"] = signup_form["username"].lower().strip()
        signup_form["password"] = signup_form["password"].strip()
        signup_form["confirmPassword"] = signup_form["confirmPassword"].strip()
        if signup_form["password"] != signup_form["confirmPassword"]:
            raise Exception("Password and confirm password do not match.")
        coordinationValidator = CoordinationValidator()
        if not coordinationValidator.is_valid_email(signup_form["email"]):
            raise Exception("The format of the email is incorrect.")
        if not coordinationValidator.is_valid_password(signup_form["password"]):
            raise Exception(
                "The password must be at least 8-character long and must container a lower case letter, an upper case letter and a digit.")
        if not coordinationValidator.is_valid_username(signup_form["username"]):
            raise Exception("The username must be at least 8-character long.")
        result["returned"] = app.coordination.create_user(
            username=signup_form["username"], password=signup_form["password"], email=signup_form["email"])
    except Exception as ex:
        result["errorMessage"] = str(ex)
    return jsonify(result)


@app.route("/user/login", methods=["POST"])
def login():
    result = get_response_model()
    try:
        authentication_result = {"username": None,
                                 "authenticated": False, "jwtToken": None}
        login_form = request.get_json()
        login_form["usernameOrEmail"] = login_form["usernameOrEmail"].lower().strip()
        login_form["password"] = login_form["password"].strip()
        authentication_result["authenticated"] = app.coordination.check_user_password(
            login_form["usernameOrEmail"], login_form["password"])
        if authentication_result["authenticated"]:
            user = app.coordination.get_user(login_form["usernameOrEmail"])
            authentication_result["username"] = user["username"]
            expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=int(
                app.coordination_config["WebAPI"]["user_session_valid_minutes"]))
            jwt_payload = {
                "username": user["username"], "loggedin": datetime.datetime.utcnow().isoformat(), "expiry": expiry.isoformat()}
            authentication_result["jwtToken"] = jwt.encode(
                jwt_payload, app.secret_key, algorithm="HS256").decode()
        result["returned"] = authentication_result
    except Exception as ex:
        result["errorMessage"] = str(ex)
    return jsonify(result)


@app.route("/user/privileges", methods=["GET"])
@token_required
def get_user_privileges(username):
    result = get_response_model()
    try:
        user = app.coordination.get_user(username)
        if "privileges" in user:
            result["returned"] = user["privileges"]
    except Exception as ex:
        result["errorMessage"] = str(ex)
    return jsonify(result)


def generate_access_token(access_info):
    access_info["created"] = datetime.datetime.utcnow().isoformat()
    return symmetrically_encrypt(access_info)


def unpack_access_token(access_token):
    access_info = symmetrically_decrypt(access_token)
    access_info["created"] = dateutil.parser.parse(access_info["created"])
    return access_info


@app.route("/user/config_access_token", methods=["GET"])
@token_required
def get_user_certificate_download_token(username):
    result = get_response_model()
    try:
        user = app.coordination.get_user(username)
        result["returned"] = generate_access_token({"user": user["username"]})
    except Exception as ex:
        result["errorMessage"] = str(ex)
    return jsonify(result)


@app.route("/user/vpn_info/<string:entry_node_id>", methods=["GET"])
@token_required
def get_user_vpn_info_by_entry_node(username, entry_node_id):
    result = get_response_model()
    try:
        machines = app.coordination.get_machines(filter={"_id": entry_node_id, "type": "entry"})
        if len(machines) > 0:
            vpn_user = app.coordination.get_user_vpnuser(username)
            vpn_info = app.coordination.generate_user_device_config_vpn_connection_info(username=username, vpn_user=vpn_user, machine=machines[0])
            result["returned"] = vpn_info
        else:
            result["returned"] = None
    except Exception as ex:
        result["errorMessage"] = str(ex)
    return jsonify(result)


@app.route("/cert/<string:access_token>", methods=["GET"])
def download_user_certificate_by_access_token(access_token):
    try:
        access_info = unpack_access_token(access_token)
        if (datetime.datetime.utcnow() - access_info["created"]) < datetime.timedelta(minutes=3):
            user = app.coordination.get_user(access_info["user"])
            pem_response = Response(
                user["certificates"]["ca-cert"], mimetype="application/x-pem-file")
            pem_response.headers["content-disposition"] = "attachment; filename=\"apptraffic_ca_%s.pem\"" % (
                user["username"])
            return pem_response

    except Exception:
        pass
    return Response("Sorry, the code is invalid or expired.", mimetype="text/plain")


@app.route("/mobileconfig/<string:access_token>", methods=["GET"])
def download_user_mobileconfig_by_access_token(access_token):
    try:
        access_info = unpack_access_token(access_token)
        if (datetime.datetime.utcnow() - access_info["created"]) < datetime.timedelta(minutes=3):
            mobileconfig_xml = app.coordination.get_user_ios_mobileconfig(access_info["user"])
            mobileconfig_response = Response(mobileconfig_xml, mimetype="application/x-apple-aspen-config")
            mobileconfig_response.headers["content-disposition"] = "attachment; filename=\"apptraffic_%s.mobileconfig\"" % (access_info["user"])
            return mobileconfig_response
    except Exception:
        pass
    return Response("Sorry, the code is invalid or expired.", mimetype="text/plain")


@app.route("/recording/start", methods=["POST"])
@token_required
def start_recording(username):
    result = get_response_model()
    try:
        record_form = request.get_json()
        user = app.coordination.get_user(username)
        record_form["entryNodeId"] = None

        if "default_entry_node" not in user:
            record_form["entryNodeId"] = app.coordination.get_machines({"type": "entry"})[
                0]["_id"]
        else:
            record_form["entryNodeId"] = user["default_entry_node"]

        session_id = app.coordination.new_session(username=user["username"], entry_node_machine_id=record_form["entryNodeId"],
                                                  exit_node_machine_id=record_form["exitNodeId"], intercept_mode=record_form["mode"], session_name=record_form["sessionName"])
        if session_id:
            app.coordination.start_session_on_entry_node(session_id=session_id)
            result["returned"] = session_id
        else:
            raise Exception("A new session could not be created")
    except Exception as ex:
        result["errorMessage"] = str(ex)
    return jsonify(result)


@app.route("/session/<string:session_id>/status", methods=["GET"])
@token_required
def check_recording_status(username, session_id):
    result = get_response_model()
    try:
        user = app.coordination.get_user(username)
        session = app.coordination.get_session(session_id)
        #if user["username"] != session["username"]:
        if not user_has_access_to_session(user, session):
            raise Exception("Unauthorised access")
        status_result = {"status": session["status"], "created": session["created"].astimezone(
        ).isoformat(), "mode": session["intercept_mode"], "exitNodeCreated": None, "ended": None }
        # resources.exit_node.created
        if "created" in session["resources"]["entry_node"]:
            status_result["entryNodeName"] = session["resources"]["entry_node"]["name"]
        if "created" in session["resources"]["exit_node"]:
            status_result["exitNodeCreated"] = session["resources"]["exit_node"]["created"].astimezone().isoformat()
        if "mitm_web_port" in session:
            status_result["mitm_web_port"] = session["mitm_web_port"]
            status_result["exit_node_public_hostname"] = socket.gethostbyname(session["resources"]["exit_node"]["public_hostname"])
        if "ended" in session:
            status_result["ended"] = session["ended"].astimezone().isoformat()
        result["returned"] = status_result
    except Exception as ex:
        result["errorMessage"] = str(ex)
    return jsonify(result)


@app.route("/session/<string:session_id>/stop", methods=["POST"])
@token_required
def stop_recording(username, session_id):
    result = get_response_model()
    try:
        user = app.coordination.get_user(username)
        session = app.coordination.get_session(session_id)
        if not user_has_access_to_session(user, session):
            raise Exception("Unauthorised access")
        app.coordination.end_session(session_id)
        result["returned"] = True
    except Exception as ex:
        result["errorMessage"] = str(ex)
    return jsonify(result)


@app.route("/session/<string:session_id>/remove", methods=["DELETE"])
@token_required
def remove_session(username, session_id):
    result = get_response_model()
    try:
        user = app.coordination.get_user(username)
        session = app.coordination.get_session(session_id)
        if not user_has_access_to_session(user, session):
            raise Exception("Unauthorised access")
        result["returned"] = app.coordination.mark_session_as_removed(
            session_id)
    except Exception as ex:
        result["errorMessage"] = str(ex)
    return jsonify(result)


@app.route("/sessions", methods=["GET"])
@token_required
def get_sessions(username):
    result = get_response_model()
    try:
        user = app.coordination.get_user(username)
        where_conditions = {"removed": {"$exists": False}}
        selected_fields = {"_id": 1, "intercept_mode": 1, "created": 1, "ended": 1, "status": 1, "name": 1}
        if not is_user_an_admin(user):
            where_conditions = {**where_conditions, "username": user["username"]}
        else:
            selected_fields = {**selected_fields, "username": 1}
        sessions = app.coordination.db["session"].find(where_conditions, selected_fields).sort("created", -1)
        session_list = list(sessions)
        result["returned"] = session_list
    except Exception as ex:
        result["errorMessage"] = str(ex)
    return jsonify(result)


def get_session_data_fileinfo(session_id):
    session = app.coordination.get_session(session_id)
    fileinfo = {}
    fileinfo["session_subdir"] = session["_id"]
    if session["intercept_mode"] == "decrypted":
        # now it offers HAR file only
        fileinfo["traffic_data_filename"] = "session_traffic.har"
        fileinfo["file_ext"] = "har"
        fileinfo["mimetype"] = "application/json"
        # if the original mitm file is offered instead, uncomment the following three lines
        # fileinfo["traffic_data_filename"] = "session_traffic.mitm"
        # fileinfo["file_ext"] = "mitm"
        # fileinfo["mimetype"] = "application/octet-stream"
    else:
        fileinfo["traffic_data_filename"] = "session_traffic.pcap"
        fileinfo["file_ext"] = "pcap"
        fileinfo["mimetype"] = "application/vnd.tcpdump.pcap"

    fileinfo["fullpath"] = os.path.join(app.coordination_config["WebAPI"]["data_storage_path"],
                                        fileinfo["session_subdir"],
                                        fileinfo["traffic_data_filename"])

    return fileinfo


@app.route("/session/<string:session_id>/download", methods=["GET"])
@token_required
def get_session_data_download_token(username, session_id):
    result = get_response_model()
    try:
        user = app.coordination.get_user(username)
        session = app.coordination.get_session(session_id)
        if not user_has_access_to_session(user, session):
            raise Exception("Unauthorised access")

        fileinfo = get_session_data_fileinfo(session_id)
        if os.path.exists(fileinfo["fullpath"]):
            result["returned"] = generate_access_token(
                {"session_id": session_id})
        else:
            result["returned"] = None
    except Exception as ex:
        result["errorMessage"] = str(ex)
    return jsonify(result)


@app.route("/session/<string:session_id>/summary", methods=["GET"])
@token_required
def get_session_traffic_summary(username, session_id):
    result = get_response_model()
    try:
        user = app.coordination.get_user(username)
        session = app.coordination.get_session(session_id)
        if not user_has_access_to_session(user, session):
            raise Exception("Unauthorised access")

        if session["intercept_mode"] != "decrypted":
            raise Exception("The analysis of non-HAR files (such as the pcap files generated in Raw and Metadata modes) is not currently supported.")

        result["returned"] = { "name": session["name"] if "name" in session else None,
                                "intercept_mode": session["intercept_mode"],
                                "created": session["created"].astimezone().isoformat(),
                                "ended": None if not "ended" in session else session["ended"].astimezone().isoformat(),
                                "entry_node_name": session["resources"]["entry_node"]["name"],
                                "exit_node_name": session["resources"]["exit_node"]["name"],
                                "analysis_generated": False, 
                                "hosts": [],
                                "request_headers": [],
                                "request_queries": [],
                                "request_cookies": [],
                                "postdata_form_params": [],
                                "postdata_json_attributes": []}

        fileinfo = get_session_data_fileinfo(session_id)

        if os.path.exists(fileinfo["fullpath"]):
            if app.coordination_config["WebAPI"]["analytics_exec_mode"] == "dask":
                analysis = Analysis_Dask(app.coordination_config["WebAPI"]["analytics_exec_dask_config_scheduler"])
                analysis.load_har_file(fileinfo["fullpath"])
                analysis_tables = analysis.get_all_summary_tables()
                result["returned"] = {**result["returned"], **analysis_tables}
                result["returned"]["analysis_generated"] = True
            else:
                analysis = Analysis()
                analysis.load_har_file(fileinfo["fullpath"])
                result["returned"]["hosts"] = analysis.extract_har_hosts_count()
                result["returned"]["request_headers"] = analysis.extract_har_request_headers()
                result["returned"]["request_queries"] = analysis.extract_har_request_queries()
                result["returned"]["request_cookies"] = analysis.extract_har_request_cookies()
                result["returned"]["postdata_form_params"] = analysis.extract_har_request_postdata_form_params()
                result["returned"]["postdata_json_attributes"] = analysis.extract_har_request_postdata_json_attributes()

    except Exception as ex:
        result["errorMessage"] = str(ex)
    return jsonify(result)


@app.route("/download/<string:access_token>", methods=["GET"])
def download_session_data_by_access_token(access_token):
    try:
        access_info = unpack_access_token(access_token)
        if (datetime.datetime.utcnow() - access_info["created"]) < datetime.timedelta(minutes=1):
            fileinfo = get_session_data_fileinfo(access_info["session_id"])
            if os.path.exists(fileinfo["fullpath"]):
                return send_from_directory(directory=os.path.join(app.coordination_config["WebAPI"]["data_storage_path"],
                                                                  fileinfo["session_subdir"]),
                                           filename=fileinfo["traffic_data_filename"],
                                           as_attachment=True,
                                           attachment_filename="%s.%s" % (
                    access_info["session_id"], fileinfo["file_ext"]),
                    mimetype=fileinfo["mimetype"])
    except Exception:
        pass
    return Response("Sorry, the code is invalid.", mimetype="text/plain")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")

