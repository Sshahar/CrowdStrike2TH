CrowdStrike = {
    'url': 'https://api.crowdstrike.com',
    'token_endpoint': '/oauth2/token',
    'stream_endpoint': '/sensors/entities/datafeed/v2',
    'app_id': '',
    'cid': '',
    'secret': '',
}

CrowdStrike['url_token'] = CrowdStrike['url'] + CrowdStrike['token_endpoint']
CrowdStrike['url_stream'] = CrowdStrike['url'] + CrowdStrike['stream_endpoint'] + f'?appId={CrowdStrike["app_id"]}'

TheHive = {
    'url': '',
    'key': '',
    'template': '',
}

