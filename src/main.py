from config import CrowdStrike
from CrowdStrike import Api


def main():
    crowdstrike_api = Api(CrowdStrike)
    crowdstrike_api.get_stream()


if __name__ == '__main__':
    main()
