import tomllib
import sys
import os

failure = 0

for root, dirs, files in os.walk("detections/"): #set path
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path,"rb") as toml:
                alert = tomllib.load(toml)

                required_fields = []
                if alert['rule']['type'] == "query": # query based aler
                    required_fields = ['description', 'name', 'risk_score', 'type', 'severity', 'query']
                elif alert['rule']['type']== "eql": # event correlation alert
                    required_fields = ['description', 'name', 'risk_score', 'type', 'severity', 'query', 'language']
                elif alert['rule']['type']== "threshold": # threshold based alert
                    required_fields = ['description', 'name', 'risk_score', 'type', 'severity', 'query', 'threshold']
                else:
                    print("Unsupported rule type found in: " + full_path)
                    break
                    
                #print(required_fields)

                #get present fields
                present_fields = []
                for table in alert:
                    for field in alert[table]:
                      present_fields.append(field)

                #missing fields:
                missing_fields = []
                for field in required_fields: 
                    if field not in present_fields:
                        missing_fields.append(field)


                if missing_fields:
                    print("Missing fields in " + file + ": " + str(missing_fields) + "\nAlert type: " + str(alert['rule']['type']))
                    failure = 1
                else: 
                    print("Validation passed for: " + file)

if failure != 0:
    sys.exit(1)
