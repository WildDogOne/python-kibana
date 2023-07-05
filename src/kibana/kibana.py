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
    def __init__(self, base_url="", username="", password="", ssl_verify=True):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.ssl_verify = ssl_verify

    def _get_pagination(self, url, payload=None, headers=None):
        if payload is None:
            payload = {}
        if headers is None:
            headers = {"Accept": "application/json"}
        run = 1
        page = 1
        while run == 1:
            params = {"perPage": 20, "page": page}
            response = requests.request(
                "GET",
                url,
                headers=headers,
                json=payload,
                params=params,
                verify=self.ssl_verify,
                auth=HTTPBasicAuth(self.username, self.password),
            )
            if response.status_code != 200:
                logger.error("Cannot get")
                logger.info(response)
                quit()
            else:
                response = response.json()
                total_pages = response["total"]
                if total_pages >= page:
                    if "output" in locals():
                        output = output + response["items"]
                    else:
                        output = response["items"]
                    page += 1
                    logger.debug(f"Page Number {page} Total Pages: {total_pages}")
                else:
                    run = 0
        return output

    def _get(self, url, payload=None, headers=None):
        if payload is None:
            payload = {}
        if headers is None:
            headers = {"Accept": "application/json"}
        response = requests.request(
            "GET",
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

    def _post(self, url, payload=None, headers=None):
        if payload is None:
            payload = {}
        if headers is None:
            headers = {"Accept": "application/json", "kbn-xsrf": ""}
        response = requests.request(
            "POST",
            url,
            headers=headers,
            json=payload,
            verify=self.ssl_verify,
            auth=HTTPBasicAuth(self.username, self.password),
        )
        pprint(response.status_code)
        if response.status_code == 200:
            return True
        elif response.status_code == 409:
            return True
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
                    return True
                elif "title" in dataview and dataview["title"] == dataview_id:
                    return True
            return False
        else:
            logger.error("No dataview id provided")
