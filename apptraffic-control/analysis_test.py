import unittest
import dask
from analysis import Analysis, Analysis_Dask
import sys

har_filename_for_tests = "/path/test.har" # set the path of the test HAR file here

class TestAnalysisDask(unittest.TestCase):
    def setUp(self):
        self.analysis = Analysis_Dask("threads")
        self.analysis.load_har_file(har_filename_for_tests)
        pass


    def test_indivdiual_export(self):
        hosts = dask.compute(self.analysis.get_har_request_postdata_form_params())
        print(hosts)


    def test_get_all_summary_tables(self):
        tables = self.analysis.get_all_summary_tables()

        self.assertTrue(len(tables["hosts"]) > 0)
        previous_count = sys.maxsize
        for entry in tables["hosts"]:
            self.assertTrue("count" in entry)
            self.assertTrue("host" in entry)
            self.assertTrue("tracker" in entry)
            # check if the list is in descending order
            self.assertGreaterEqual(previous_count, entry["count"])
            previous_count = entry["count"]

        remaining_tables = ["request_headers", "request_queries",
                            "request_cookies", "postdata_form_params", "postdata_json_attributes"]

        for table_key in remaining_tables:
            self.assertTrue(len(tables[table_key]) > 0)
            for row in tables[table_key]:
                self.assertTrue("name" in row)
                self.assertTrue("value" in row)
                self.assertTrue("host" in row)
                self.assertTrue("tracker" in row)
        
        pass


class TestAnalysis(unittest.TestCase):
    def setUp(self):
        self.analysis = Analysis()
        self.analysis.load_har_file(har_filename_for_tests)
        pass

    def test_get_all_summary_tables(self):
        self.test_extract_har_hosts_count()
        self.test_extract_har_request_headers()
        self.test_extract_har_request_queries()
        self.test_extract_har_request_cookies()
        self.test_extract_har_request_postdata_form_params()
        self.test_extract_har_request_postdata_json_attributes()

    
    def test_extract_har_hosts_count(self):
        host_method_list = self.analysis.extract_har_hosts_count()
        self.assertTrue(len(host_method_list) > 0) # non-empty list
        previous_count = sys.maxsize
        for entry in host_method_list:
            self.assertTrue("count" in entry)
            self.assertTrue("host" in entry)
            self.assertTrue("tracker" in entry)
            # check if the list is in descending order
            self.assertGreaterEqual(previous_count, entry["count"])
            previous_count = entry["count"]
        pass

    def test_extract_har_request_headers(self):
        request_headers = self.analysis.extract_har_request_headers()
        # print(request_headers)
        self.assertTrue(len(request_headers) > 0)
        for header in request_headers:
            self.assertTrue("name" in header)
            self.assertTrue("value" in header)
            self.assertTrue("host" in header)
            self.assertTrue("tracker" in header)
        pass

    def test_extract_har_request_queries(self):
        queries = self.analysis.extract_har_request_queries()
        self.assertTrue(len(queries) > 0)
        for query in queries:
            self.assertTrue("name" in query)
            self.assertTrue("value" in query)
            self.assertTrue("host" in query)
            self.assertTrue("tracker" in query)
        pass

    def test_extract_har_request_cookies(self):
        cookies = self.analysis.extract_har_request_cookies()
        self.assertTrue(len(cookies) > 0)
        for cookie in cookies:
            self.assertTrue("name" in cookie)
            self.assertTrue("value" in cookie)
            self.assertTrue("host" in cookie)
            self.assertTrue("tracker" in cookie)
        pass

    def test_extract_har_request_postdata_form_params(self):
        form_parameters = self.analysis.extract_har_request_postdata_form_params()
        self.assertTrue(len(form_parameters) > 0)
        for parameter in form_parameters:
            self.assertTrue("name" in parameter)
            self.assertTrue("value" in parameter)
            self.assertTrue("host" in parameter)
            self.assertTrue("tracker" in parameter)
        pass

    def test_extract_har_request_postdata_json_attributes(self):
        json_attributes = self.analysis.extract_har_request_postdata_json_attributes()
        print(json_attributes)
        self.assertTrue(len(json_attributes) > 0)
        for attribute in json_attributes:
            self.assertTrue("name" in attribute)
            self.assertTrue("value" in attribute)
            self.assertTrue("host" in attribute)
            self.assertTrue("tracker" in attribute)
        pass
