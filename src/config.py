CrowdStrike = {
    'url': '',
    'token_endpoint': '',
    'stream_endpoint': '',
    'app_id': '',
    'cid': '',
    'secret': '',
}

CrowdStrike['url_token'] = CrowdStrike['url'] + CrowdStrike['token_endpoint']
CrowdStrike['url_stream'] = CrowdStrike['url'] + CrowdStrike['stream_endpoint'] + f'?appId={CrowdStrike["app_id"]}'

TheHive = {
    'url': '',
    'key': '',
}