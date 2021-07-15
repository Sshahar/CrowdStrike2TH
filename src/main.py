from config import CrowdStrike
from CrowdStrike import Api


def print_detect(detect):
    for k, v in detect.items():
        print(k, v)


def main():
    crowdstrike_api = Api(key=CrowdStrike.get("cid"), secret=CrowdStrike.get("secret"))

    detects = crowdstrike_api.get_detects()

    print_detect(detects['resources'][3])


if __name__ == '__main__':
    main()
