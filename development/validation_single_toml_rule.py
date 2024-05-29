import tomllib
import sys

#import a toml file
file = "TOML/alert_example.toml"
with open(file, "rb") as toml: 
    alert = tomllib.load(toml)


#for table in alert:
#    print("\n"+table+ ":")
#    for field in alert[table]:
#        print(field)

#required fields: 

if alert['rule']['type'] == "query": # query based aler
    required_fields = ['description', 'name', 'risk_score', 'type', 'severity', 'query']
elif alert['rule']['type']== "eql": # event correlation alert
    required_fields = ['description', 'name', 'risk_score', 'type', 'severity', 'query', 'language']
elif alert['rule']['type']== "threshold": # threshold based alert
    required_fields = ['description', 'name', 'risk_score', 'type', 'severity', 'query', 'threshold']

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

#print(required_fields)
#print(present_fields)
#print(missing_fields)

if missing_fields:
    print("Missing fields in " + file + ": " + str(missing_fields) + "\nAlert type: " + str(alert['rule']['type']))
else: 
    print("Validation passed for: " + file)

