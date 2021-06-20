import json
import uuid
from thehive4py.exceptions import AlertException
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact, CustomFieldHelper
from config import TheHive

api = TheHiveApi(TheHive['url'], TheHive['key'], version=4)

# Prepare the sample Alert
sourceRef = str(uuid.uuid4())[0:6]
alert = Alert(title='New Alert',
              tlp=3,
              tags=['TheHive4Py', 'sample'],
              description='N/A',
              type='external',
              source='instance1',
              sourceRef=sourceRef,
              )

# Create the alert
try:
    response = api.create_alert(alert)

    # Print the JSON response
    print(json.dumps(response.json(), indent=4, sort_keys=True))

except AlertException as e:
    print("Alert create error: {}".format(e))
