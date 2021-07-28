import re
import datetime


class DetectionParser:
    def __init__(self):
        pass

    @staticmethod
    def parse_detect(detect):
        """

        :param detect:
        :type detect: dict
        :return: ['Event Id', 'Customer Name', 'Event Date/Time', 'Host/User', 'Severity', 'Status', 'Description']
        """
        d = detect
        customer = None

        if d['device'].get('tags') is not None:
            match = re.search("/(.*)", d['device'].get('tags')[0])
            customer = match.group(1)

        time_str = d['created_timestamp']
        if '.' in time_str:
            time_str = time_str.split('.')[0]+'Z'
        dt = datetime.datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%SZ").astimezone()
        time_str = dt.strftime('%B')[:3] + dt.strftime('. %d, %Y %H:%M:%S')

        return [d['cid'], customer, time_str, d['device']['hostname']+'/'+d['behaviors'][0]['user_name'],
                d['max_severity_displayname'], d['status'],
                f"{d['behaviors'][0].get('technique')}/{d['behaviors'][0].get('display_name')}: "
                f"{d['behaviors'][0].get('description')}",
                ]
