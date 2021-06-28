from config import CrowdStrike
from CrowdStrike import Api


def main():
    crowdstrike_api = Api(CrowdStrike)
    detects = crowdstrike_api.get_detects()

    print(detects)


if __name__ == '__main__':
    main()
