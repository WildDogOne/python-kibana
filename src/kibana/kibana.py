import json
from pprint import pprint
import logging
import requests
from requests.auth import HTTPBasicAuth
from datetime import datetime, timedelta, timezone

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger()
logger.setLevel(logging.INFO)
from pathlib import Path


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
                "kbn-xsrf": "",
            }
            self.api_key = True
        else:
            self.headers = headers
            self.api_key = False
        self.ssl_verify = ssl_verify

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
        if self.api_key:
            response = requests.request(
                "PUT",
                url,
                headers=headers,
                json=payload,
                verify=self.ssl_verify,
            )
        else:
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
            pprint(response.json())

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

    def _post(self, url, payload=None, headers=None, params=None, files=None):
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
                files=files,
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
                files=files,
            )
        # response.raise_for_status()
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

    def create_dataview(
        self,
        name: str,
        title: str,
        timeFieldName: str = "@timestamp",
        space: str = None,
    ) -> bool:
        """
        Create a dataview
        :param name: Mandatory name of the dataview.
        :param title: Mandatory dataview search rule (eg logs-*).
        :param timeFieldName: Optional field name of timestamp, defaults to @timestamp.
        :param space: Optional Kibana space id; if set, prefix path with /s/{space}.
        :return: Parsed JSON response.
        """

        if space:
            path = f"/s/{space}/api/data_views/data_view"
        else:
            path = f"/api/data_views/data_view"
        url = self.base_url + path
        body = {"data_view": {}}
        if name:
            body["data_view"]["name"] = name
        if title:
            body["data_view"]["title"] = title
        if timeFieldName:
            body["data_view"]["timeFieldName"] = timeFieldName

        response = self._post(url, payload=body, headers=self.headers)
        return response

    def update_dataview(
        self,
        name: str,
        title: str,
        viewId: str,
        timeFieldName: str = "@timestamp",
        space: str = None,
    ) -> bool:
        """
        Create a dataview
        :param name: Mandatory name of the dataview.
        :param title: Mandatory dataview search rule (eg logs-*).
        :param viewId: Mandatory viewId of the dataview.
        :param timeFieldName: Optional field name of timestamp, defaults to @timestamp.
        :param space: Optional Kibana space id; if set, prefix path with /s/{space}.
        :return: Parsed JSON response.
        """

        if space:
            path = f"/s/{space}/api/data_views/data_view/{viewId}"
        else:
            path = f"/api/data_views/data_view/{viewId}"
        url = self.base_url + path
        body = {"data_view": {}}
        if name:
            body["data_view"]["name"] = name
        if title:
            body["data_view"]["title"] = title
        if timeFieldName:
            body["data_view"]["timeFieldName"] = timeFieldName

        response = self._post(url, payload=body, headers=self.headers)
        return response

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

    def get_detection_engine_tags(self):
        url = self.base_url + "/api/detection_engine/tags"
        return self._get(url)

    def get_rule(self, rule_id):
        url = self.base_url + "/api/detection_engine/rules"
        params = {"id": rule_id}
        return self._get(url, params=params)

    def find_rule(self, rule_name: str = None):
        url = self.base_url + "/api/detection_engine/rules/_find"
        params = {}
        if rule_name:
            params["filter"] = f'alert.attributes.name:"{rule_name}"'
        return self._get(url, params=params)

    def get_all_rules(self):
        page = 1
        output_data = []
        while True:
            url = (
                self.base_url
                + "/api/detection_engine/rules/_find?per_page=100&page="
                + str(page)
            )
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

    def import_exception_lists(
        self: object,
        ndjson_path: str,
        overwrite: bool = False,
        create_new_copy: bool = False,
        space: str = None,
        timeout: int = 30,
    ) -> dict[str, any]:
        """
        Import exception lists and items from an NDJSON file into Kibana/Elastic Security.

        :param ndjson_path: Path to NDJSON file exported from exception lists.
        :param overwrite: If True, overwrite existing lists/items with same ids.
        :param create_new_copy: If True, force new list_id/item_id values on import.
        :param space: Optional Kibana space id; if given, path becomes '/s/{space}/api/...'.
        :return: Parsed JSON response from the API.
        """
        ndjson_file = Path(ndjson_path)
        if not ndjson_file.is_file():
            raise FileNotFoundError(f"NDJSON file not found: {ndjson_file}")
        if space:
            path = f"/s/{space}/api/exception_lists/_import"
        else:
            path = "/api/exception_lists/_import"
        url = self.base_url + path

        params = {
            "overwrite": str(overwrite).lower(),
            "create_new_copy": str(create_new_copy).lower(),
        }

        headers = {
            "kbn-xsrf": "true",
        }

        with ndjson_file.open("rb") as f:
            files = {
                "file": (ndjson_file.name, f, "application/x-ndjson"),
            }
            resp = self._post(url, headers=headers, params=params, files=files)

        # Raise for HTTP errors (401, 403, 500, etc.) [attached_file:1]
        return resp.json()

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

    def get_exception_container(self, id=None, list_id=None):
        url = self.base_url + "/api/exception_lists"
        params = {}
        if id:
            params["id"] = id
        if list_id:
            params["list_id"] = list_id
        return self._get(url, params=params)

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

    def create_rule_exception_items(
        self: object,
        rule_id: str,
        items: list[dict[str, any]],
        space: str | None = None,
    ) -> dict[str, any]:
        """
        Create exception items that apply to a single detection rule.

        :param rule_id: The detection rule ID from the API (not rule name).
        :param items: List of exception item definitions (same shape as in docs).
        :param space: Optional Kibana space id; if set, prefix path with /s/{space}.
        :return: Parsed JSON response.
        """
        if space:
            path = f"/s/{space}/api/detection_engine/rules/{rule_id}/exceptions"
        else:
            path = f"/api/detection_engine/rules/{rule_id}/exceptions"
        url = self.base_url + path

        headers = {
            "kbn-xsrf": "true",
            "Content-Type": "application/json",
        }

        body = {"items": items}

        resp = self._post(
            url,
            headers=headers,
            payload=body,
        )
        return resp.json()

    def get_saved_objects(
        self: object,
        type: str,
        space: str | None = None,
    ) -> list[dict, any]:
        """
        Get Saved objects by type
        :param type: Mandatory saved object type eg. dashboard.
        :param space: Optional Kibana space id; if set, prefix path with /s/{space}.
        :return: Parsed JSON response.
        """
        if space:
            path = f"/s/{space}/api/saved_objects/_find"
        else:
            path = f"/api/saved_objects/_find"
        url = self.base_url + path
        params = {"per_page": 100, "page": 1, "type": type}
        saved_objects = []
        while True:
            resp = self._get(
                url,
                params=params,
            )
            saved_objects.extend(resp["saved_objects"])
            if resp["total"] <= len(saved_objects):
                break
            else:
                params["page"] = params["page"] + 1
        return saved_objects

    def get_dataviews(self, space: str = None) -> list[dict, any]:
        """
        Get all dataviews defined in kibana.
        :param type: Mandatory saved object type eg. dashboard.
        :param space: Optional Kibana space id; if set, prefix path with /s/{space}.
        :return: Parsed JSON response.
        """
        if space:
            path = f"/s/{space}/api/data_views"
        else:
            path = f"/api/data_views"
        url = self.base_url + path
        response = self._get(url)
        return response["data_view"]

    def get_connectors(self, space: str = None) -> list[dict, any]:
        """
        Get all connectores defined in kibana.
        :param space: Optional Kibana space id; if set, prefix path with /s/{space}.
        :return: Parsed JSON response.
        """
        if space:
            path = f"/s/{space}/api/actions/connectors"
        else:
            path = f"/api/actions/connectors"
        url = self.base_url + path
        response = self._get(url)
        return response

    def update_connector(
        self, connector_id: int, config: object, space: str = None
    ) -> list[dict, any]:
        """
        Update a connector defined in kibana.
        :param connector_id: Mandatory ID of the connector to update.
        :param config: Configuration object.
        :param space: Optional Kibana space id; if set, prefix path with /s/{space}.
        :return: Parsed JSON response.
        """
        if space:
            path = f"/s/{space}/api/actions/connector/{connector_id}"
        else:
            path = f"/api/actions/connector/{connector_id}"
        url = self.base_url + path
        response = self._put(url, payload=config)
        return response

    def generate_attack_discovery(
        self,
        connectorName: str,
        connector_id: str,
        alertsIndexPattern: str = ".alerts-security.alerts-default",
        size: int = 100,
        anonymizationFields: dict = None,
        filter: dict = None,
        space: str = None,
    ) -> list[dict, any]:
        """
        Run Attack Discovery.
        :param filter: Optional Filter for alerts.
        :param space: Optional Kibana space id; if set, prefix path with /s/{space}.
        :return: Parsed JSON response.
        """
        if not anonymizationFields:
            anonymizationFields = []
        if space:
            path = f"/s/{space}/api/attack_discovery/_generate"
        else:
            path = f"/api/attack_discovery/_generate"
        url = self.base_url + path
        if not anonymizationFields:
            anonymizationFields = [
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "@timestamp",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "aKiJW5gB4U27o8XO8oLf",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "Ransomware.feature",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "saiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "Ransomware.files.data",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "sqiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "Ransomware.files.entropy",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "s6iJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "Ransomware.files.extension",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "tKiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "Ransomware.files.metrics",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "taiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "Ransomware.files.operation",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "tqiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "Ransomware.files.path",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "t6iJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "Ransomware.files.score",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "uKiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "Ransomware.version",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "uaiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "_id",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "Z6iJW5gB4U27o8XO8oLf",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "agent.id",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "aaiJW5gB4U27o8XO8oLf",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "cloud.availability_zone",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "aqiJW5gB4U27o8XO8oLf",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "cloud.provider",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "a6iJW5gB4U27o8XO8oLf",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "cloud.region",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "bKiJW5gB4U27o8XO8oLf",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "destination.ip",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "baiJW5gB4U27o8XO8oLf",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "dns.question.name",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "bqiJW5gB4U27o8XO8oLf",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "dns.question.type",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "b6iJW5gB4U27o8XO8oLf",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "event.category",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "cKiJW5gB4U27o8XO8oLf",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "event.dataset",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "caiJW5gB4U27o8XO8oLf",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "event.module",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "cqiJW5gB4U27o8XO8oLf",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "event.outcome",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "c6iJW5gB4U27o8XO8oLf",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "file.Ext.original.path",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "dKiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "file.hash.sha256",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "daiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "file.name",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "dqiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "file.path",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "d6iJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "group.id",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "eKiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "group.name",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "eaiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "host.asset.criticality",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "eqiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "host.name",
                    "allowed": True,
                    "anonymized": True,
                    "namespace": "default",
                    "id": "e6iJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "host.os.name",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "fKiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "host.os.version",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "faiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "host.risk.calculated_level",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "fqiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "host.risk.calculated_score_norm",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "f6iJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "kibana.alert.original_time",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "gKiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "kibana.alert.risk_score",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "gaiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "kibana.alert.rule.description",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "gqiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "kibana.alert.rule.name",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "g6iJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "kibana.alert.rule.references",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "hKiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "kibana.alert.rule.threat.framework",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "haiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "kibana.alert.rule.threat.tactic.id",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "hqiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "kibana.alert.rule.threat.tactic.name",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "h6iJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "kibana.alert.rule.threat.tactic.reference",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "iKiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "kibana.alert.rule.threat.technique.id",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "iaiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "kibana.alert.rule.threat.technique.name",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "iqiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "kibana.alert.rule.threat.technique.reference",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "i6iJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "kibana.alert.rule.threat.technique.subtechnique.id",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "jKiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "kibana.alert.rule.threat.technique.subtechnique.name",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "jaiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "kibana.alert.rule.threat.technique.subtechnique.reference",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "jqiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "kibana.alert.severity",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "j6iJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "kibana.alert.workflow_status",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "kKiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "message",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "kaiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "network.protocol",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "kqiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.Ext.memory_region.bytes_compressed_present",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "nKiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.Ext.memory_region.malware_signature.all_names",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "naiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.Ext.memory_region.malware_signature.primary.matches",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "nqiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.Ext.memory_region.malware_signature.primary.signature.name",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "n6iJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.Ext.token.integrity_level_name",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "oKiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.args",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "k6iJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.code_signature.exists",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "lKiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.code_signature.signing_id",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "laiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.code_signature.status",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "lqiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.code_signature.subject_name",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "l6iJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.code_signature.trusted",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "mKiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.command_line",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "maiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.executable",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "mqiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.exit_code",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "m6iJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.hash.md5",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "oaiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.hash.sha1",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "oqiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.hash.sha256",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "o6iJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.name",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "pKiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.parent.args",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "paiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.parent.args_count",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "pqiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.parent.code_signature.exists",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "p6iJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.parent.code_signature.status",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "qKiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.parent.code_signature.subject_name",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "qaiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.parent.code_signature.trusted",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "qqiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.parent.command_line",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "q6iJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.parent.executable",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "rKiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.parent.name",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "raiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.pe.original_file_name",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "rqiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.pid",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "r6iJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "process.working_directory",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "sKiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "rule.name",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "uqiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "rule.reference",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "u6iJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "source.ip",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "vKiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "threat.framework",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "vaiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "threat.tactic.id",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "vqiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "threat.tactic.name",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "v6iJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "threat.tactic.reference",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "wKiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "threat.technique.id",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "waiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "threat.technique.name",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "wqiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "threat.technique.reference",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "w6iJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "threat.technique.subtechnique.id",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "xKiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "threat.technique.subtechnique.name",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "xaiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "threat.technique.subtechnique.reference",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "xqiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "user.asset.criticality",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "x6iJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "user.domain",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "yKiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "user.name",
                    "allowed": True,
                    "anonymized": True,
                    "namespace": "default",
                    "id": "yaiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "user.risk.calculated_level",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "yqiJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "user.risk.calculated_score_norm",
                    "allowed": True,
                    "anonymized": False,
                    "namespace": "default",
                    "id": "y6iJW5gB4U27o8XO8oLg",
                },
                {
                    "timestamp": "2025-07-30T13:33:44.029Z",
                    "createdAt": "2025-07-30T13:33:44.029Z",
                    "field": "user.target.name",
                    "allowed": True,
                    "anonymized": True,
                    "namespace": "default",
                    "id": "zKiJW5gB4U27o8XO8oLg",
                },
            ]
        config = {
            "anonymizationFields": anonymizationFields,
            "alertsIndexPattern": alertsIndexPattern,
            "replacements": {},
            "size": size,
            "subAction": "invokeAI",
            "apiConfig": {
                "connectorId": connector_id,
                "actionTypeId": ".gen-ai",
            },
            "connectorName": connectorName,
            "end": "now",
            "start": "now-7d",
        }
        if filter:
            config["filter"] = filter
        response = self._post(url, payload=config)
        return response.json()

    def get_attack_discovery(
        self,
        attack_discovery_id: int = None,
        space: str = None,
    ) -> list[dict, any]:
        """
        Run Attack Discovery by ID or optionall all.
        :param attack_discovery_id: Optional attack discovery ID.
        :param space: Optional Kibana space id; if set, prefix path with /s/{space}.
        :return: Parsed JSON response.
        """
        url_path = "/api/attack_discovery/generations"
        path = self.space_url(url_path, space)
        if attack_discovery_id:
            path = f"{path}/{attack_discovery_id}"
        url = self.base_url + path
        response = self._get(url)
        return response["generations"]

    def space_url(self, url: str, space: str = None) -> str:
        """
        Make an URL Path Space Specific if space is defined
        :param url: URL path
        :param space: Optional Space Name
        :return:
        """
        if space:
            return f"/s/{space}{url}"
        else:
            return url

    def find_attack_discoveries(
        self,
        status: str = None,
        space: str = None,
    ) -> list[dict, any]:
        """
        Find attack discoveries
        :param status: Values are acknowledged, closed, or open.
        :param space: Optional Kibana space id; if set, prefix path with /s/{space}.
        :return: Parsed JSON response.
        """
        url_path = "/api/attack_discovery/_find"
        url = self.base_url + url_path
        params = {"status": status}
        response = self._get_pagination(url, params=params)
        return response

    def share_attack_discoveries(
        self,
        ids: list[int],
        space: str = None,
    ) -> list[dict, any]:
        """
        Share a list of attack discovery IDs.
        :param ids: List of attack discovery IDs.
        :param space: Optional Kibana space id; if set, prefix path with /s/{space}.
        :return: Parsed JSON response.
        """
        url_path = "/api/attack_discovery/_bulk"
        url = self.base_url + url_path
        json_data = {
            "update": {
                "ids": ids,
                "visibility": "shared",
            },
        }
        response = self._post(url, payload=json_data)
        return response
