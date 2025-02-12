import json
from pprint import pprint
import logging
import requests
from requests.auth import HTTPBasicAuth

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger()
logger.setLevel(logging.INFO)


class kibana:
    def __init__(
        self,
        base_url=None,
        username=None,
        password=None,
        api_key=None,
        ssl_verify=True,
        headers=None,
    ):
        if not api_key and (not username and not password):
            raise ValueError("No API Key or Username/Password provided")
        if not base_url:
            raise ValueError("No Base URL provided")
        else:
            self.base_url = base_url
        if username:
            self.username = username
        if password:
            self.password = password
        if api_key:
            self.headers = {
                "Authorization": f"ApiKey {api_key}",
                "Accept": "application/json",
            }
            self.api_key = True
        else:
            self.api_key = False
        self.ssl_verify = ssl_verify
        self.headers = headers

    def _get_pagination(self, url, headers=None, params={}):
        if self.headers is None:
            headers = {"Accept": "application/json"}
        else:
            headers = self.headers
        run = 1
        page = 1
        output = []
        while run == 1:
            params["page"] = page
            if self.api_key:
                response = requests.request(
                    "GET",
                    url,
                    headers=headers,
                    params=params,
                    verify=self.ssl_verify,
                )
            else:
                response = requests.request(
                    "GET",
                    url,
                    headers=headers,
                    params=params,
                    verify=self.ssl_verify,
                    auth=HTTPBasicAuth(self.username, self.password),
                )
            if response.status_code != 200:
                logger.error("Cannot get")
                logger.info(response)
                return False
            else:
                response = response.json()
                if len(response["data"]) == 0:
                    run = 0
                else:
                    output += response["data"]
                    page += 1
        return output

    def _get(self, url, payload=None, headers=None, params=None):
        if payload is None:
            payload = {}
        if self.headers is None:
            headers = {"Accept": "application/json"}
        else:
            headers = self.headers
        if self.api_key:
            response = requests.request(
                "GET",
                url,
                headers=headers,
                json=payload,
                verify=self.ssl_verify,
                params=params,
            )
        else:
            response = requests.request(
                "GET",
                url,
                headers=headers,
                json=payload,
                verify=self.ssl_verify,
                auth=HTTPBasicAuth(self.username, self.password),
                params=params,
            )
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            logger.error(f"Error 404\n{response.url}")
            logger.error(response.json())
        else:
            pprint(response.status_code)

    def _put(self, url, payload=None, headers=None):
        if payload is None:
            payload = {}
        if self.headers is None:
            headers = {"Accept": "application/json", "kbn-xsrf": ""}
        else:
            headers = self.headers
        response = requests.request(
            "PUT",
            url,
            headers=headers,
            json=payload,
            verify=self.ssl_verify,
            auth=HTTPBasicAuth(self.username, self.password),
        )
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            logger.error(f"Error 404\n{response.url}")
            logger.error(response.json())
        else:
            pprint(response.status_code)

    def _delete(self, url, headers=None):
        if self.headers is None:
            headers = {"Accept": "application/json", "kbn-xsrf": ""}
        else:
            headers = self.headers
        response = requests.request(
            "DELETE",
            url,
            headers=headers,
            verify=self.ssl_verify,
            auth=HTTPBasicAuth(self.username, self.password),
        )
        if response.status_code == 200:
            return response.text
        elif response.status_code == 404:
            logger.error(f"Error 404\n{response.url}")
            logger.error(response.json())
        else:
            logger.error(response.status_code)
            logger.error(response.json())

    def _post(self, url, payload=None, headers=None, params=None):
        if payload is None:
            payload = {}
        if self.headers is None:
            headers = {"Accept": "application/json", "kbn-xsrf": ""}
        else:
            headers = self.headers
            headers["kbn-xsrf"] = ""
        if self.api_key:
            response = requests.request(
                "POST",
                url,
                headers=headers,
                json=payload,
                verify=self.ssl_verify,
                params=params,
            )
        else:
            response = requests.request(
                "POST",
                url,
                headers=headers,
                json=payload,
                verify=self.ssl_verify,
                auth=HTTPBasicAuth(self.username, self.password),
                params=params,
            )
        if response.status_code == 200:
            return response
        elif response.status_code == 409:
            return response
        elif response.status_code == 404:
            logger.error(f"Error 404\n{response.url}")
            logger.error(response.json())
        else:
            logger.error(f"Unable to POST\nStatus Code: {response.status_code}")
            logger.error(response.json())

    def create_dataview(self, dataview=None, space_id="default"):
        if dataview:
            dataview = {"data_view": dataview}
            logger.info(dataview)
            url = self.base_url + "/s/" + space_id + "/api/data_views/data_view"

            payload = dataview
            return self._post(url, payload=payload)
        else:
            logger.error("No dataview provided")

    def get_dataview(self, dataview_id=None, space_id="default"):
        if dataview_id:
            url = self.base_url + "/s/" + space_id + "/api/data_views"
            dataviews = self._get(url)
            for dataview in dataviews["data_view"]:
                if "name" in dataview and dataview["name"] == dataview_id:
                    return dataview and dataview["id"]
                elif "title" in dataview and dataview["title"] == dataview_id:
                    return dataview and dataview["id"]
            return False
        else:
            logger.error("No dataview id provided")

    def delete_dataview(self, dataview_id=None, space_id="default"):
        if dataview_id:
            url = (
                self.base_url
                + "/s/"
                + space_id
                + "/api/data_views/data_view/"
                + dataview_id
            )
            return self._delete(url)
        else:
            logger.error("No dataview id provided")

    def install_package(self, package_name=None, package_version=None):
        if package_name:
            url = self.base_url + "/api/fleet/epm/packages/" + package_name.lower()
            if package_version:
                url = url + "/" + package_version
            else:
                package_version = self._get(url)["item"]["version"]
                url = url + "/" + package_version
            return self._post(url)
        else:
            logger.error("No Package Name provided")

    def get_install_status(self, package_name=None):
        if package_name:
            url = self.base_url + "/api/fleet/epm/packages/" + package_name.lower()
            installed = self._get(url)["response"]["status"]
            if installed == "installed":
                return True
            else:
                return False
        else:
            logger.error("No Package Name provided")

    def delete_package(self, package_name=None):
        if package_name:
            url = self.base_url + "/api/fleet/epm/packages/" + package_name.lower()
            package_version = self._get(url)["item"]["version"]
            url = url + "/" + package_version
            return self._delete(url)
        else:
            logger.error("No Package Name provided")

    def update_package(self, package_name=None):
        if package_name:
            url = self.base_url + "/api/fleet/epm/packages/" + package_name.lower()
            package_version = self._get(url)["item"]["version"]
            url = url + "/" + package_version
            return self._put(url)
        else:
            logger.error("No Package Name provided")

    def create_agent_policy(self, name=None, namespace="default"):
        if name:
            url = self.base_url + "/api/fleet/agent_policies"

            payload = {
                "name": name,
                "namespace": namespace,
                "monitoring_enabled": ["metrics", "logs"],
            }
            return self._post(url, payload)
        else:
            logger.error("No Agent Policy Name provided")

    def get_agent_policy(self, name=None):
        if name:
            url = self.base_url + "/api/fleet/agent_policies"
            policies = self._get(url)
            for policy in policies["items"]:
                if policy["name"] == name:
                    return policy
            return False
        else:
            logger.error("No Agent Policy Name provided")

    def delete_agent_policy(self, name=None):
        if name:
            policy = self.get_agent_policy(name)
            if policy:
                url = self.base_url + "/api/fleet/agent_policies/delete"

                payload = {"agentPolicyId": policy["id"]}
                return self._post(url, payload)
            return False
        else:
            logger.error("No Agent Policy Name provided")

    def get_package(self, package_name=None):
        if package_name:
            url = self.base_url + "/api/fleet/epm/packages/" + package_name.lower()
            return self._get(url)["response"]
        else:
            logger.error("No Package Name provided")

    def create_package_policy(
        self,
        package_policy_name=None,
        package_name=None,
        namespace="default",
        agent_policy=None,
    ):
        if package_policy_name:
            url = self.base_url + "/api/fleet/package_policies"
            agent_policy_id = self.get_agent_policy(name=agent_policy)["id"]
            package = self.get_package(package_name=package_name)
            return package["data_streams"][0]["streams"][0]

            payload = {
                "description": "",
                "enabled": True,
                "inputs": [
                    {
                        "enabled": True,
                        "policy_template": "suricata",
                        "streams": [package["data_streams"][0]["streams"][0]],
                        "type": "logfile",
                    }
                ],
                "name": package_policy_name,
                "namespace": namespace,
                "output_id": "",
                "package": {
                    "name": "suricata",
                    "title": "Suricata Events",
                    "version": "1.7.0",
                },
                "policy_id": agent_policy_id,
            }
            return self._post(url, payload)
        else:
            logger.error("No Package Policy Name provided")

    def get_service_token(self, token_name=None, token_value=None):
        url = self.base_url + "/api/fleet/service_tokens"
        return self._post(url).json()["value"]

    def get_enrolment_key(self, agent_policy_name=None):
        if agent_policy_name:
            url = self.base_url + "/api/fleet/enrollment_api_keys"
            keys = self._get(url)
            # pprint(keys)
            for key in keys["items"]:
                if key["policy_id"] == agent_policy_name:
                    return key["api_key"]
        else:
            logger.error("No Agent Policy Name provided")

    def get_fleet_outputs(self):
        url = self.base_url + "/api/fleet/outputs"
        return self._get(url)

    def get_fleet_output(self, output_name=None):
        if output_name:
            existing_outputs = self.get_fleet_outputs()
            for output in existing_outputs["items"]:
                if output["name"] == output_name:
                    return output["id"]
            else:
                return False
        else:
            return False

    def create_fleet_output(
        self,
        type="elasticsearch",
        hosts=None,
        output_id=None,
        output_name=None,
        is_default=True,
        is_default_monitoring=True,
        ca_trusted_fingerprint=None,
        config_yaml=None,
    ):
        if hosts and output_name:
            url = self.base_url + "/api/fleet/outputs"
            payload = {
                "name": output_name,
                "hosts": hosts,
                "type": type,
                "is_default": is_default,
                "is_default_monitoring": is_default_monitoring,
            }
            if output_id:
                payload["id"] = output_id
            if config_yaml:
                payload["config_yaml"] = config_yaml
            if ca_trusted_fingerprint:
                payload["ca_sha256"] = ca_trusted_fingerprint
            return self._post(url, payload)
        else:
            logger.error("No Hosts or output Name provided")

    def update_fleet_output(
        self,
        output_name=None,
        type=None,
        hosts=None,
        output_id=None,
        is_default=None,
        is_default_monitoring=None,
        ca_trusted_fingerprint=None,
        config_yaml=None,
    ):
        if output_name:
            output_id = self.get_fleet_output(output_name)
            if output_id:
                url = self.base_url + "/api/fleet/outputs/" + output_id
                payload = {}
                if type:
                    payload["type"] = type
                if hosts:
                    payload["hosts"] = hosts
                if is_default is not None:
                    payload["is_default"] = is_default
                if is_default_monitoring is not None:
                    payload["is_default_monitoring"] = is_default_monitoring
                if config_yaml:
                    payload["config_yaml"] = config_yaml
                if ca_trusted_fingerprint:
                    payload["ca_sha256"] = ca_trusted_fingerprint
                return self._put(url, payload)
            else:
                logger.error("No Output ID found")
        else:
            logger.error("No Output Name provided")

    def delete_fleet_output(self, output_name=None):
        if output_name:
            output_id = self.get_fleet_output(output_name)
            if output_id:
                url = self.base_url + "/api/fleet/outputs/" + output_id
                return self._delete(url)
            else:
                logger.error("No Output ID found")
        else:
            logger.error("No Output Name provided")

    def load_prebuilt_rules(self):
        url = self.base_url + "/api/detection_engine/rules/prepackaged"
        return self._put(url)

    def get_prebuilt_rules_status(self):
        url = self.base_url + "/api/detection_engine/rules/prepackaged/_status"
        return self._get(url)

    def get_rule(self, rule_id):
        url = self.base_url + "/api/detection_engine/rules"
        params = {"id": rule_id}
        return self._get(url, params=params)

    def get_all_rules(self):
        page = 1
        output_data = []
        while True:
            url = self.base_url + "/api/detection_engine/rules/_find?page=" + str(page)
            x = self._get(url)
            if len(x["data"]) > 0:
                output_data += x["data"]
                page += 1
            else:
                break
        return output_data

    def get_all_exception_lists(self):
        return self._get_pagination(self.base_url + "/api/exception_lists/_find")

    def export_exception_list(self, id=None, list_id=None, namespace_type=None):
        url = self.base_url + "/api/exception_lists/_export"
        params = {"id": id, "list_id": list_id, "namespace_type": namespace_type}
        results = self._post(url, params=params)
        outputs = []
        for result in results.text.split("\n"):
            if len(result) > 0:
                outputs.append(json.loads(result))
        return outputs

    def bulk_change_rules(
        self, rule_ids=None, action="enable", query=None, edit=None, duplicate=None
    ):
        if rule_ids:
            payload = {"ids": rule_ids, "action": action}
            if query:
                payload["query"] = query
            if edit:
                payload["edit"] = edit
            if duplicate:
                payload["duplicate"] = duplicate
            url = self.base_url + "/api/detection_engine/rules/_bulk_action"
            return self._post(url, payload)
        else:
            logger.error("No Rules ids provided")

    def enable_prebuild_ml_job(self, job_name=None):
        url = self.base_url + "/api/ml/jobs/force_start_datafeeds"
        if job_name:
            payload = {"datafeedIds": [f"datafeed-{job_name}"]}
            return self._post(url, payload)
        else:
            logger.error("No Job Name provided")

    def disable_prebuild_ml_job(self, job_name=None):
        url = self.base_url + "/api/ml/jobs/stop_datafeeds"
        if job_name:
            payload = {"datafeedIds": [f"datafeed-{job_name}"]}
            return self._post(url, payload)
        else:
            logger.error("No Job Name provided")

    def get_exception_container(self, container_name=None):
        url = self.base_url + "/api/exception_lists/_find"
        if container_name:
            exception_containers = self._get_pagination(url)
            for exception_container in exception_containers:
                if container_name in exception_container["name"]:
                    return exception_container
            return False
            # return exception_containers
        else:
            logger.error("No Container Name provided")

    def create_exception_container(
        self, container_name=None, container_type="detection", description=None
    ):
        url = self.base_url + "/api/exception_lists"
        if container_name:
            payload = {
                "name": container_name,
                "type": container_type,
                "list_id": container_name.replace(" ", "_").lower(),
            }
            if description:
                payload["description"] = description
            else:
                payload["description"] = container_name
            return self._post(url, payload)
        else:
            logger.error("No Container Name provided")

    def delete_exception_container(self, container_name=None, list_id=None):
        if container_name and not list_id:
            container = self.get_exception_container(container_name)
            if container:
                list_id = container["list_id"]
            else:
                logger.error("No Container found")
        if list_id:
            url = self.base_url + "/api/exception_lists?list_id=" + list_id
            return self._delete(url)
        else:
            logger.error("No Container Name or List ID provided")

    def attach_container_to_rule(
        self, container_name=None, rule_name=None, list_id=None
    ):
        if container_name and not list_id:
            container = self.get_exception_container(container_name)
            if container:
                list_id = container["list_id"]
            else:
                logger.error("No Container found")

    def post_get_alerts(
        self,
        filter_closed: bool = True,
        fields: dict = None,
        size: int = 1000,
        filter_terms: dict = None,
    ):
        url = self.base_url + "/api/detection_engine/signals/search"
        print(url)
        payload = {
            "_source": True,
            "aggs": {},
            # "fields": ["string"],
            "runtime_mappings": {},
            "size": size,
            # "sort": "string",
            "track_total_hits": True,
            "query": {"bool": {}},
        }
        if filter_closed:
            payload["query"]["bool"]["must_not"] = [
                {"match_phrase": {"signal.status": "closed"}}
            ]
        if filter_terms:
            filter_list = []
            for field, values in filter_terms.items():
                filter_list.append(
                    {"terms": {field: values if isinstance(values, list) else [values]}}
                )
            payload["query"]["bool"]["filter"] = filter_list
        if fields:
            if not isinstance(fields, list):
                fields = [fields]
            payload["fields"] = fields
            payload["_source"] = False

        results = self._post(url, payload=payload)
        if results.status_code == 200:
            return results.json()["hits"]["hits"]
        else:
            return results

    def post_close_alert(self, signal_ids):
        url = self.base_url + "/api/detection_engine/signals/status"
        payload = {"signal_ids": signal_ids, "status": "closed"}
        self._post(url, payload)

    def post_ack_alert(self, signal_ids):
        url = self.base_url + "/api/detection_engine/signals/status"
        payload = {"signal_ids": signal_ids, "status": "in-progress"}
        self._post(url, payload)
