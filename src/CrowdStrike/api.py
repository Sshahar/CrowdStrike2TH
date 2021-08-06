import requests
import json
from falconpy.oauth2 import OAuth2
from falconpy.event_streams import Event_Streams
from falconpy.detects import Detects


class Api:
    def __init__(self, key="", secret="", base_url='https://api.crowdstrike.com', appId=""):
        """

        :param key:
        :param secret:
        :param base_url:
        """
        self._key = key
        self._secret = secret
        self._app_id = appId
        self._api_auth = OAuth2(creds={"client_id": key, "client_secret": secret}, base_url=base_url)
        self._api_detects = Detects(auth_object=self._api_auth)
        self._api_event_streams = Event_Streams(auth_object=self._api_auth)

    def get_stream(self):
        """Get Event-Stream, parses it, and prints it's events."""
        response = self._api_event_streams.listAvailableStreamsOAuth2(appId=self._app_id)
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

    def get_detects(self, since=None):
        """
        https://falcon.crowdstrike.com/documentation/86/detections-monitoring-apis
        :return:
        """
        filter = None
        if since is not None:
            filter = f"first_behavior:>'{since}'"

        response = self._api_detects.QueryDetects(filter=filter, limit=1000, sort="first_behavior")

        detect_ids = response["body"]["resources"]
        detects = self.get_these_detects(detect_ids)

        return detects

    def get_these_detects(self, detect_ids):
        return self._api_detects.GetDetectSummaries(body={"ids": detect_ids})["body"]
