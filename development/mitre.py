import requests
import os
import tomllib

#this script maps the alert to the MITRE ATT&CK matrix tactics & techniques

#gather all data from mitre on attack matrix: tactics, techniques:
url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
headers = {
    'accept': 'application/json'
}
mitreData = requests.get(url, headers=headers).json()
mitreMapped = {} #holds all the tactics & techniques of MITRE ATT&CK matrix

#def getMapping(mitreData):
all_tactics = []
#Create MITRE object:
for object in mitreData['objects']:
    tactics = [] 
    if object['type'] == "attack-pattern": 
        if 'external_references' in object:
            for reference in object['external_references']:
                if 'external_id' in reference:
                    #ensure id is a T-id: 
                    if ((reference['external_id'].startswith("T"))):
                        if 'kill_chain_phases' in object:
                            for tactic in object['kill_chain_phases']:
                                tactics.append(tactic['phase_name'])
                                all_tactics.append(tactic['phase_name'])   
                        #print(reference)
                        technique = reference['external_id']
                        name = object['name']
                        url = reference['url']

                        if 'x_mitre_deprecated' in object:
                            deprecated = object['x_mitre_deprecated']
                            filtered_object = {'tactics': str(tactics), 'technique': technique, 'name' : name, 'url' : url, 'deprecated': deprecated}
                            mitreMapped[technique] = filtered_object
                        else: 
                            filtered_object = {'tactics': str(tactics), 'technique': technique, 'name' : name, 'url' : url, 'deprecated': "False"}
                            mitreMapped[technique] = filtered_object

#View MITRE ATT&CK info:
#print(mitreMapped) 
#lookup MITRE data via T-id 
#key = T-id
#print(mitreMapped['T1144'])
#check if deprecated:
#print(mitreMapped['T1123']['deprecated'])

mitre_tactics_unique = list(set(all_tactics))
mitre_tactics_unique.sort()
#print(mitre_tactics_unique)


#Mapping of our alerts to MITRE standard:
alert_data = {}

for root, dirs, files in os.walk("/home/nvb/Detection_Engineering2/test_single_rule/"): #set path to folder with alerts
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path,"rb") as toml:
                alert = tomllib.load(toml)
                filtered_object_array = [] #create array for each file (each alert can have one or more MITRE mappings)
                if alert['rule']['threat'][0]['framework'] == "MITRE ATT&CK": #only get MITRE mappings, not others
                    for threat in alert['rule']['threat']:
                        technique_id = threat['technique'][0]['id']
                        technique_name = threat['technique'][0]['name']
                        if 'tactic' in threat:
                            tactic = threat['tactic']['name']
                        else: 
                            tactic = "none"

                        if 'subtechnique' in threat['technique'][0]:
                            subtechnique_id = threat['technique'][0]['subtechnique'][0]['id']
                            subtechnique_name = threat['technique'][0]['subtechnique'][0]['name']
                        else:
                            subtechnique_id = "none"
                            subtechnique_name = "none"

                        #print(file + ":" + tactic + ":" + technique_id + ":" + technique_name + ":" + subtechnique_id + ":" + subtechnique_name)

                        MITRE_mapping = {'tactic': tactic, 'technique_id': technique_id, 'technique_name': technique_name, 'subtechnique_id': subtechnique_id, 'subtechnique_name': subtechnique_name}
                        filtered_object_array.append(MITRE_mapping)
                        alert_data[file] = filtered_object_array #key is file name = rule name, value = MITRE mapping(s)


# Validate MITRE Mappings for each rule:
zero_faults = True
for file in alert_data:
    for line in alert_data[file]:
        tactic = line['tactic'].lower()
        technique_id = line['technique_id']
        subtechnique_id = line['subtechnique_id']

        #print(file+" : "+tactic+" : "+technique_id+" : "+subtechnique_id)

        # Check that MITRE Tactic exists
        if tactic not in mitre_tactics_unique:
            print("The MITRE Tactic supplied does not exist: " + "\"" + tactic + "\"" + " in " + file)
            zero_faults = False

        # Check that MITRE Technique ID is valid
        try: 
            if mitreMapped[technique_id]:
                pass
        except KeyError:
            print("Invalid MITRE Technique ID: " + "\"" + technique_id + "\"" + " in " + file)
            zero_faults = False

        # Check that MITRE T-ID matches Name
        try:
            mitre_name = mitreMapped[technique_id]['name']
            alert_name = line['technique_name']
            if mitre_name != alert_name:
                print("MITRE Technique ID and Name mismatch in " + file + "\nEXPECTED: " + "\"" + mitre_name + "\"" + " GIVEN: " + "\"" + alert_name + "\"")
                zero_faults = False
        except KeyError:
            pass

        # Check that sub-T-ID matches Name
        try:
            if subtechnique_id != "none":
                mitre_name = mitreMapped[subtechnique_id]['name']
                alert_name = line['subtechnique_name']
                if mitre_name != alert_name:
                    print("MITRE Sub-Technique ID and Name mismatch in " + file + "\nEXPECTED: " + "\"" + mitre_name + "\"" + " GIVEN: " + "\"" + alert_name + "\"")
                    zero_faults = False
        except KeyError:
            pass

        # Check whether technique is deprecated
        try:
            if mitreMapped[technique_id]['deprecated'] == True:
                print("Deprecated MITRE Technique ID: " + "\"" + technique_id + "\"" + " in " + file)
                zero_faults = False
        except KeyError:
            pass

if zero_faults:
    print("MITRE ATT&CK Mappings: Correct")
