from config import CrowdStrike
from CrowdStrike import Api


def print_detect(detect):
    for k, v in detect.items():
        print(k, v)


def main():
    crowdstrike_api = Api(key=CrowdStrike.get("cid"), secret=CrowdStrike.get("secret"))

    detects = crowdstrike_api.get_detects(since=4)

    # print_detect(detects['resources'][3])

    for i, detect in enumerate(detects['resources']):
        if i == 10:
            break
        print(detect['behaviors'][0].get('sha256'))

    print(detects['resources'][3])


if __name__ == '__main__':
    main()
