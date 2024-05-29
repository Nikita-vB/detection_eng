import requests

# url = <kibana host>:<port>/api/<endpoint>
# kibana host: our demo instance url = https://detectionengineeringclass101.kb.us-central1.gcp.cloud.es.io:9243/
# endpoint: detection_engine/rules
url = "https://detectionengineeringclass101.kb.us-central1.gcp.cloud.es.io:9243/api/detection_engine/rules"

api_key = "bWF2b3VJOEIwOWdZR2hTYVVaUGw6blc2SUtxdEdUWTJwN2NIcnRoNHZIZw=="
headers = {
    'Content-Type': 'application/json;charset=UTF-8',
    'kbn-xsrf': 'true',
    'Authorization': 'ApiKey ' + api_key
}

data = """
{
  "rule_id": "process_started_by_ms_office_program",
  "risk_score": 50,
  "description": "Process started by MS Office program - possible payload",
  "interval": "1h", 
  "name": "MS Office child process - Test Rule Upload via API",
  "severity": "low",
  "tags": [
   "child process",
   "ms office"
   ],
  "type": "query",
  "from": "now-70m", 
  "query": "process.parent.name:EXCEL.EXE or process.parent.name:MSPUB.EXE or process.parent.name:OUTLOOK.EXE or process.parent.name:POWERPNT.EXE or process.parent.name:VISIO.EXE or process.parent.name:WINWORD.EXE",
  "language": "kuery",
  "filters": [
     {
      "query": {
         "match": {
            "event.action": {
               "query": "Process Create (rule: ProcessCreate)",
               "type": "phrase"
            }
         }
      }
     }
  ],
  "enabled": true
}
"""

elastic_data = requests.post(url, headers=headers, data=data).json()
print(elastic_data)
