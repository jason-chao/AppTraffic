import pandas as pd
import dask
import dask.dataframe as dd
import dask.bag as db
import json_flatten
import json
import re


class Analysis_Dask:

    def __init__(self, dask_config_scheduler="threads"):
        """
        This class generates analytics of a traffic session saved in HAR format using Dask
        """
        dask.config.set(scheduler=dask_config_scheduler)
        self.har_json = {}
        self.har_entry_requests = []
        self.registered_headers = []
        self.trackers = []
        self.host_tracker_mapping = {}
        self.load_registered_http_headers()
        self.load_etip_trackers()
        pass

    def load_registered_http_headers(self):
        """
        Loads the HTTP headers registered pursuant to RFC 3864 into the class from the CSV files from https://www.iana.org/assignments/message-headers/message-headers.xml
        Dask is not use because tests shoewed no performance gain in reading two small csv files
        """
        permanent_http_headers_df = pd.read_csv(
            "./datasets/perm-headers.csv")  # The CSV files is stored locally
        permanent_http_headers_df.insert(0, "type", "permanent")
        provisional_http_headers_df = pd.read_csv(
            "./datasets/prov-headers.csv")  # The CSV files is stored locally
        provisional_http_headers_df.insert(0, "type", "provisional")
        # RFC 3864 stores permanent and provisional headers in two separate csv files.  Merge them into a single dataframe here.
        http_headers_df = pd.concat(
            [permanent_http_headers_df, provisional_http_headers_df])
        http_headers_df = http_headers_df[http_headers_df["Protocol"] == "http"]
        self.registered_headers = http_headers_df["Header Field Name"].str.lower(
        ).to_list()  # Convert the headers into lower case to easy comparision later
        # :authority is a special header from MITMProxy/Web to indicate the Common Name of the SSL certificate
        self.registered_headers.append(":authority")
        pass

    def load_etip_trackers(self):
        """
        Loads a list of trackers from the Exodus Tracker Investigation Platform (ETIP) database downloaded from https://etip.exodus-privacy.eu.org/
        """
        trackers_file = open("./datasets/etip-trackers.json", "r")
        etip_data = json.loads(trackers_file.read())
        # Filter out the tracker entries without network signatures
        self.trackers = [
            tracker for tracker in etip_data["trackers"] if tracker["network_signature"]]
        trackers_file.close()

    def load_har(self, har_json):
        """
        Loads the HAR json object into the class
        Args: 
           har_json (dict): the parsed HAR json dict/object
        Returns:
           list of dict:
              host: server hostname in the request
              and all other attributes in HAR.log.entries.request
        """
        self.har_json = har_json
        self.har_entry_requests = [e["request"]
                                   for e in self.har_json["log"]["entries"]]
        self.har_entry_requests = db.from_sequence(
            har_json["log"]["entries"]).pluck("request")  # At this stage, only requests are loaded.  Responds will be implemented in the future.
        self.har_entry_requests = self.har_entry_requests.map(lambda req: {**req, "host": next(
                                                             (header["value"] for header in req["headers"]
                                                              if header["name"] in [":authority", "Host"]), "N/A")})
        #self.host_tracker_mapping = self.har_entry_requests.pluck("host").distinct().map(
        #    lambda h: {"host": h, "tracker": self.detect_tracker_by_host(h)})
        #self.har_entry_requests = self.har_entry_requests.map(
        #    lambda req: {**req, "tracker": self.detect_tracker_by_host(req["host"])})

    def load_har_file(self, filename):
        # No performance gain to use Dask to read a single JSON file
        har_file = open(filename, "r")
        self.load_har(json.loads(har_file.read()))
        har_file.close()

    def detect_tracker_by_host(self, host):
        if host:
            if host in self.host_tracker_mapping:
                return self.host_tracker_mapping[host]
            else:
                for tracker in self.trackers:
                    if re.search(tracker["network_signature"], host):
                        self.host_tracker_mapping[host] = tracker["name"]
                        return tracker["name"]
                self.host_tracker_mapping[host] = None
        return None

    #def map_host_to_tracker(self, host):
    #    return next((pair["tracker"] for pair in self.host_tracker_mapping if pair["host"] == host), None)

    def get_all_summary_tables(self):
        if len(self.har_json["log"]["entries"]) <= 0:
            return {}

        summary_table_tasks = {"hosts": self.get_har_hosts_count(),
                               "request_headers": self.get_har_request_headers(),
                               "request_queries": self.get_har_request_queries(),
                               "request_cookies": self.get_har_request_cookies(),
                               "postdata_form_params": self.get_har_request_postdata_form_params(),
                               "postdata_json_attributes": self.get_har_request_postdata_json_attributes()
                               }
        summary_tables = dask.compute(summary_table_tasks)

        if len(summary_tables) > 0:
            return summary_tables[0]

        return None

    def get_har_hosts_count(self):
        har_headers_method_df = dask.delayed(pd.json_normalize)(
            self.har_entry_requests, record_path=["headers"])
        hosts_df = har_headers_method_df.loc[har_headers_method_df["name"].isin(
            [":authority", "Host"])].groupby(["value"]).count().reset_index()
        hosts_df = hosts_df.rename(columns={"value": "host", "name": "count"})
        hosts_df = hosts_df.sort_values(by="count", ascending=False)
        hosts_df = hosts_df.assign(
            tracker=hosts_df["host"].map(self.detect_tracker_by_host))
        return hosts_df.to_dict("records")

    def get_har_request_headers(self):
        #har_headers_df = dask.delayed(pd.json_normalize)(
        #    self.har_entry_requests, record_path=["headers"], meta=["host", "tracker"])
        har_headers_df = dask.delayed(pd.json_normalize)(
            self.har_entry_requests, record_path=["headers"], meta=["host"])
        har_headers_df = har_headers_df[~har_headers_df["name"].str.lower().isin(
            self.registered_headers)].drop_duplicates()
        har_headers_df = har_headers_df.assign(
            tracker=har_headers_df["host"].map(self.detect_tracker_by_host))
        return har_headers_df.to_dict("records")

    def get_har_request_queries(self):
        #har_queryString_df = dask.delayed(pd.json_normalize)(self.har_entry_requests, record_path=[
        #    "queryString"], meta=["host", "tracker"])
        har_queryString_df = dask.delayed(pd.json_normalize)(self.har_entry_requests, record_path=[
            "queryString"], meta=["host"])
        har_queryString_df = har_queryString_df.drop_duplicates()
        har_queryString_df = har_queryString_df.assign(
            tracker=har_queryString_df["host"].map(self.detect_tracker_by_host))
        return har_queryString_df.to_dict("records")

    def get_har_request_cookies(self):
        #har_cookies_df = dask.delayed(pd.json_normalize)(self.har_entry_requests, record_path=[
        #            "cookies"], meta=["host", "tracker"])
        har_cookies_df = dask.delayed(pd.json_normalize)(self.har_entry_requests, record_path=[
            "cookies"], meta=["host"])
        har_cookies_df = har_cookies_df.drop(
            columns=["httpOnly", "secure"], errors="ignore").drop_duplicates()  # these columns do not exist if cookies are entires are entirely absent from HAR.  so errors must be suppressed.
        har_cookies_df = har_cookies_df.assign(
            tracker=har_cookies_df["host"].map(self.detect_tracker_by_host))
        return har_cookies_df.to_dict("records")

    def get_har_request_postdata_form_params(self):
        #http_posts_data = [{**er["postData"], "host": er["host"], "tracker": er["tracker"]}
        #                   for er in self.har_entry_requests if "postData" in er]
        http_posts_data = [{**er["postData"], "host": er["host"]}
                           for er in self.har_entry_requests if "postData" in er]
        if len(http_posts_data) <= 0:
            return []
        har_postData_df = dask.delayed(pd.json_normalize)(
            http_posts_data, record_path=["params"], meta=["host"])
        har_postData_df = har_postData_df.drop_duplicates()
        har_postData_df = har_postData_df.assign(
            tracker=har_postData_df["host"].map(self.detect_tracker_by_host))
        return har_postData_df.to_dict("records")

    def try_json_loads(self, json_text):
        try:
            return json.loads(json_text)
        except json.decoder.JSONDecodeError:
            pass
        return None

    def get_har_request_postdata_json_attributes(self):

        http_posts_data = [{**er["postData"], "host": "" if "host" not in er else er["host"]}
                           for er in self.har_entry_requests if "postData" in er]

        post_data_json_texts = [(post_data["text"], post_data["host"])
                                for post_data in http_posts_data if post_data["mimeType"].startswith("application/json")]

        json_texts_hosts_bag = db.from_sequence(post_data_json_texts)

        post_data_json_array_bag = json_texts_hosts_bag.starmap(
            lambda json_text, host: (self.try_json_loads(json_text), host))

        post_data_json_array_bag = post_data_json_array_bag.filter(
            lambda element: element[0])

        flattened_json_bag = post_data_json_array_bag.starmap(lambda json_obj, host:
                                                              map(lambda element: {"name": element[0], "value": element[1], "host": host, "tracker": self.detect_tracker_by_host(host)}, list(json_flatten.flatten(json_obj).items())))

        request_postdata_json_attributes_dict = flattened_json_bag.flatten().distinct(
            lambda o: json.dumps(o, sort_keys=True).lower())

        return request_postdata_json_attributes_dict


class Analysis:

    def __init__(self):
        self.har_json = {}
        self.har_entry_requests = []
        self.registered_headers = []
        self.trackers = []
        self.host_tracker_mapping = {}
        self.load_registered_http_headers()
        self.load_etip_trackers()
        pass

    def load_registered_http_headers(self):
        # Load the headers registered pursuant to RFC 3864
        # the lists are from https://www.iana.org/assignments/message-headers/message-headers.xml
        permanent_http_headers_df = pd.read_csv("./datasets/perm-headers.csv")
        permanent_http_headers_df["type"] = "permanent"
        provisional_http_headers_df = pd.read_csv(
            "./datasets/prov-headers.csv")
        provisional_http_headers_df["type"] = "provisional"
        http_headers_df = pd.concat(
            [permanent_http_headers_df, provisional_http_headers_df])
        http_headers_df = http_headers_df[http_headers_df["Protocol"] == "http"]
        http_headers_df["Header Field Name"] = http_headers_df["Header Field Name"].str.lower()
        self.registered_headers = http_headers_df["Header Field Name"].to_list(
        )
        # special headers from MITM
        self.registered_headers.append(":authority")
        pass

    def load_etip_trackers(self):
        trackers_file = open("./datasets/etip-trackers.json", "r")
        etip_data = json.loads(trackers_file.read())
        # Filter out the tracker entries without network signatures
        self.trackers = [
            tracker for tracker in etip_data["trackers"] if tracker["network_signature"]]
        trackers_file.close()

    def detect_tracker_by_host(self, host):
        if host:
            if host in self.host_tracker_mapping:
                return self.host_tracker_mapping[host]
            else:
                for tracker in self.trackers:
                    if re.search(tracker["network_signature"], host):
                        self.host_tracker_mapping[host] = tracker["name"]
                        return tracker["name"]
                self.host_tracker_mapping[host] = None
        return None

    def no_entires(self):
        return len(self.har_entry_requests) <= 0

    def load_har(self, har_json):
        self.har_json = har_json
        self.har_entry_requests = [e["request"]
                                   for e in self.har_json["log"]["entries"]]
        for request in self.har_entry_requests:
            request["host"] = next((header["value"] for header in request["headers"] if header["name"] in [
                                   ":authority", "Host"]), None)
            request["tracker"] = self.detect_tracker_by_host(request["host"])

    def load_har_file(self, filename):
        har_file = open(filename, "r")
        self.load_har(json.loads(har_file.read()))
        har_file.close()

    def extract_har_hosts_count(self):
        if self.no_entires():
            return []
        har_headers_method_df = pd.json_normalize(
            self.har_entry_requests, record_path=["headers"])
        hosts_df = har_headers_method_df.loc[har_headers_method_df["name"].isin(
            [":authority", "Host"])].groupby(["value"]).count().reset_index()
        hosts_df.rename(
            columns={"value": "host", "name": "count"}, inplace=True)
        hosts_df.sort_values(by="count", ascending=False, inplace=True)
        # hosts_df["tracker"] = hosts_df["host"].map(self.detect_tracker)
        hosts_df = hosts_df.assign(
            tracker=hosts_df["host"].map(self.detect_tracker_by_host))
        return hosts_df.to_dict("records")

    def extract_har_request_headers(self):
        if self.no_entires():
            return []
        har_headers_df = pd.json_normalize(self.har_entry_requests, record_path=[
                                           "headers"], meta=["host", "tracker"])
        har_headers_df["name"] = har_headers_df["name"].str.lower()
        har_headers_df = har_headers_df[~har_headers_df["name"].isin(
            self.registered_headers)].drop_duplicates()
        return har_headers_df.to_dict("records")

    def extract_har_request_queries(self):
        har_queryString_df = pd.json_normalize(self.har_entry_requests, record_path=[
                                               "queryString"], meta=["host", "tracker"])
        har_queryString_df = har_queryString_df.drop_duplicates()
        return har_queryString_df.to_dict("records")

    def extract_har_request_cookies(self):
        if self.no_entires():
            return []
        har_cookies_df = pd.json_normalize(self.har_entry_requests, record_path=[
                                           "cookies"], meta=["host", "tracker"])
        har_cookies_df = har_cookies_df.drop(
            columns=["httpOnly", "secure"], errors="ignore").drop_duplicates()  # these columns do not exist if cookies are entires are entirely absent from HAR.  so errors must be suppressed.

        return har_cookies_df.to_dict("records")

    def extract_har_request_postdata_form_params(self):
        if self.no_entires():
            return []
        http_posts_data = [{**er["postData"], "host": er["host"], "tracker": er["tracker"]}
                           for er in self.har_entry_requests if "postData" in er]
        har_postData_df = pd.json_normalize(
            http_posts_data, record_path=['params'], meta=["host", "tracker"])
        har_postData_df = har_postData_df.drop_duplicates()
        return har_postData_df.to_dict("records")

    def extract_har_request_postdata_json_attributes(self):
        if self.no_entires():
            return []
        http_posts_data = [{**er["postData"], "host": er["host"]}
                           for er in self.har_entry_requests if "postData" in er]
        post_data_json_texts = [(post_data["text"], post_data["host"])
                                for post_data in http_posts_data if post_data["mimeType"].startswith("application/json")]
        post_data_json_array = []
        for (json_text, host) in post_data_json_texts:
            try:
                post_data_json_array.append((json.loads(json_text), host))
            except json.decoder.JSONDecodeError:
                pass
        post_data_df = pd.DataFrame(columns=["name", "value", "host"])
        for (post_data_json, host) in post_data_json_array:
            flattened = json_flatten.flatten(post_data_json)
            for flattened_key in flattened.keys():
                post_data_df = post_data_df.append(
                    {"name": flattened_key, "value": flattened[flattened_key], "host": host, "tracker": self.detect_tracker_by_host(host)}, ignore_index=True)
        post_data_df = post_data_df.drop_duplicates().sort_values(by="name")
        # post_data_df["tracker"] = post_data_df["host"].map(self.detect_tracker)
        return post_data_df.to_dict("records")
