import requests
import json

from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session


class Api:
    def __init__(self, key="", secret="", base_url='https://api.crowdstrike.com'):
        """

        :param key:
        :param secret:
        :param base_url:
        """
        self._url_token = base_url + '/oauth2/token'
        self._url_stream = base_url + '/sensors/entities/datafeed/v2'
        self._key = key
        self._secret = secret

        self._client = OAuth2Session(client=BackendApplicationClient(self._key))
        self._client.fetch_token(token_url=self._url_token, client_secret=self._secret)

    def get_stream(self):
        """Get Event-Stream, parses it, and prints it's events."""
        response = self._client.get(self._url_stream)
        url_data_feed, token, refresh_session_url = self._parse_response(response)
        self._client.auto_refresh_url = refresh_session_url
        self._get_events(url_data_feed, token)

    @staticmethod
    def _parse_response(response):
        """
        Parse response of URL stream.
        :param response: response to parse
        :return: url_data_feed to get events from, authentication token and refresh_session_url
        """
        j = json.loads(response.text)
        url_data_feed = j['resources'][0]['dataFeedURL']
        token = j.get('resources')[0].get('sessionToken').get('token')
        refresh_session_url = j['resources'][0]['refreshActiveSessionURL']

        return url_data_feed, token, refresh_session_url

    @staticmethod
    def _get_events(url_data_feed, token):
        """
        https://falcon.crowdstrike.com/documentation/89/event-streams-apis
        Prints events from data feed using token to authenticate.
        :param url_data_feed: URL to get events from
        :param token: token to authenticate
        """
        resp = requests.get(url_data_feed + "&offset=0",
                            stream=True,
                            headers={'Accept': 'application/json',
                                     'Authorization': f'Token {token}'})
        for line in resp.iter_lines():

            # filter out keep-alive new lines
            if line:
                decoded_line = line.decode('utf-8')
                print(json.loads(decoded_line))

    def get_detects(self, since):
        """
        https://falcon.crowdstrike.com/documentation/86/detections-monitoring-apis
        :return:
        """
        response = self._client.get("https://api.crowdstrike.com/detects/queries/detects/v1",
                                    params={'sort': 'first_behavior', 'limit': 1000,
                                            'filter': f"first_behavior:>'{since}'"},
                                    )
        j = json.loads(response.text)
        detect_ids = j['resources']

        res2 = self._client.post("https://api.crowdstrike.com/detects/entities/summaries/GET/v1",
                                json={"ids": detect_ids},
                                headers={
                                    "Accept": "application/json",
                                    "Content-Type": "application/json"
                                })

        j = json.loads(res2.text)

        return j
