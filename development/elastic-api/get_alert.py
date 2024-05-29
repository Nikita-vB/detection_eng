import requests
import os

# url = <kibana host>:<port>/api/<endpoint>
# kibana host: our demo instance url = https://detectionengineeringclass101.kb.us-central1.gcp.cloud.es.io:9243/
# endpoint: detection_engine/rules
url = "https://detectionengineeringclass101.kb.us-central1.gcp.cloud.es.io:9243/api/detection_engine/rules?rule_id="
rule_id = "2f2f4939-0b34-40c2-a0a3-844eb7889f43" #from example rule "collection_posh_audio_capture"
full_path = url + rule_id

# GET request url query:
# id - GET /api/detection_engine/rules?id=<id>
# rule_id - GET /api/detection_engine/rules?rule_id=<rule_id>



api_key = os.environ['ELASTIC_KEY']
headers = {
    'Content-Type': 'application/json;charset=UTF-8',
    'kbn-xsrf': 'true',
    'Authorization': 'ApiKey ' + api_key
}


elastic_data = requests.get(full_path, headers=headers).json()
print(elastic_data)