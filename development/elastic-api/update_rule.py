import requests
import tomllib
import os

# url = <kibana host>:<port>/api/<endpoint>
# kibana host: our demo instance url = https://detectionengineeringclass101.kb.us-central1.gcp.cloud.es.io:9243/
# endpoint: detection_engine/rules
url = "https://detectionengineeringclass101.kb.us-central1.gcp.cloud.es.io:9243/api/detection_engine/rules"

api_key = os.environ['ELASTIC_KEY']
headers = {
    'Content-Type': 'application/json;charset=UTF-8',
    'kbn-xsrf': 'true',
    'Authorization': 'ApiKey ' + api_key
}

# use custom_test_alerts
#for root, dirs, files in os.walk("detections/"): #set path
for root, dirs, files in os.walk("detections/"): #set path -> folder for testing single rule
    for file in files:
        print(file)
        data = "{\n"
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            
            with open(full_path,"rb") as toml:
                alert = tomllib.load(toml)
                print(str(alert['rule']['name']))

                #set required fields:
                required_fields = []              
                if alert['rule']['type'] == "query": # query based aler
                    required_fields = ['author', 'description', 'name', 'rule_id', 'risk_score', 'type', 'severity', 'query', 'threat']
                elif alert['rule']['type']== "eql": # event correlation alert
                    required_fields = ['author', 'description', 'name', 'rule_id', 'risk_score', 'type', 'severity', 'query', 'language', 'threat']
                elif alert['rule']['type']== "threshold": # threshold based alert
                    required_fields = ['author', 'description', 'name', 'rule_id', 'risk_score', 'type', 'severity', 'query', 'threshold', 'threat']
                else:
                    print("Unsupported rule type found in: " + full_path)
                    break
                
                #parsing for each data type
                for field in alert['rule']:
                    if field in required_fields:
                        if type(alert['rule'][field]) == list:
                            data += "  " + "\"" + field + "\": " + str(alert['rule'][field]).replace("'","\"") + ",\n"
                        elif type(alert['rule'][field]) == str:
                            
                            if field == "query":
                                data += "  " + "\"" + field + "\": \"" + str(alert['rule'][field]).replace("\\","\\\\").replace("\"", "\\\"").replace("\n", " ") + "\"," + "\n"

                            else:
                                data += "  " + "\"" + field + "\": \"" + str(alert['rule'][field]).replace("\n"," ").replace("\"", "\\\"").replace("\\", "\\\\") + "\"," + "\n"
                        elif type(alert['rule'][field]) == int:
                            data += "  " + "\"" + field + "\": " + str(alert['rule'][field]) + ",\n"                    
                data += "  \"enabled\": true\n}"
        
        #print(data)
        rule_id = [alert]["rule"]["rule_id"]
        url = url + "?rule_id=" + rule_id

        elastic_data = requests.put(url, headers=headers, data=data).json()

        print(elastic_data)
        print("##########")