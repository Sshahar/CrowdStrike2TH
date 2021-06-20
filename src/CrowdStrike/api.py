import requests
import json

from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session


class Api:
    def __init__(self, config):
        self.url_token = config['url_token']
        self.url_stream = config['url_stream']
        self.key = config['cid']
        self.secret = config['secret']

        self.client = OAuth2Session(client=BackendApplicationClient(self.key))
        self.client.fetch_token(token_url=self.url_token, client_secret=self.secret)

    def get_stream(self):
        """Get Event-Stream, parses it, and prints it's events."""
        response = self.client.get(self.url_stream)
        url_data_feed, token, refresh_session_url = self._parse_response(response)
        self.client.auto_refresh_url = refresh_session_url
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