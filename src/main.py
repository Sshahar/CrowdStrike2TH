from config import CrowdStrike
from CrowdStrike import Api


def print_detect(detect):
    for k, v in detect.items():
        print(k, v)


def main():

    crowdstrike_api = Api(key=CrowdStrike.get("client_id"),
                          secret=CrowdStrike.get("client_secret"),
                          appId=CrowdStrike.get("appId")
                          )

    detects = crowdstrike_api.get_detects()
    for detection in detects["resources"]:
        print_detect(detection)


if __name__ == '__main__':
    main()
