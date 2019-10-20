#!/usr/bin/python

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: Nessus.sc scan results module
short_description: Fetch and parse Nessus.sc scan results
description:
    - Nessus.sc scan results are in SCAP (XML) format
    - This module connects to Nessus.sc to retrieve the results of a scan
    - Unzips the file and extract the content in JSON format
    - work in progress ...
version_added: "2.4"
author: Jesus Fonteboa (#hiperesfera in GitHub)
options:
    scan_location:
        description:
            - Location of the Nessus scan report
        required: true
notes:
    - work in progress 
    - this module still needs a lot of error checking/handling and integration with Nessus.sc via pyTanable module
    - At the moment, it relies in having the Nessus scan in a local file
requirements:
    - Requires the following module to be installed 'pyTenable'
    - Tested with Ansible 2.8.6 version and Python 2.7.16
'''

EXAMPLES = '''
- name: Fetch and parse Nessus.sc scan results
  nessus-scan-results 
      scan_location: "./nessus_report.xml"
  register: output
'''

RETURN = '''
changed:
    description: If changed or not (true if results completed)
    type: bool
output:
    description: Nessus scan results extracted from the SCAP file and formated in JSON 
    type: JSON
'''


import xml.etree.ElementTree as ET
        

from ansible.module_utils.basic import AnsibleModule
import time

def run_module():

    module_args = dict(
        scan_location=dict(type='str', required=True)
        )

    result = dict(
        changed=False,
        original_message='',
        message=''
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    
    if module.check_mode:
        return result
 
    scan_location = module.params['scan_location']
    

    root = ET.parse(scan_location).getroot()
    time.sleep(2)

    nessus_dict = {}
    nessus_matrix = []
    

    for tag in root.findall('Report/ReportHost'):
        machine_name = tag.get('name')
        nessus_dict = { machine_name:{} } 
        tags = root.findall('Report/ReportHost/HostProperties/tag')
        os = [i.text for i in tags if i.get('name') == 'operating-system'][0]
        ip = [i.text for i in tags if i.get('name') == 'host-ip'][0]
        netbios = [i.text for i in tags if i.get('name') == 'netbios-name'][0]
        
        for tag in root.findall('Report/ReportHost/ReportItem'):
            pluginID = tag.get('pluginID')
            port = tag.get('port')
            severity = int(tag.get('severity'))
            pluginName = tag.get('pluginName')  #tab is a dictionary so you can use tag['severity'] 
            description = tag.find('description').text
            synopsis = tag.find('synopsis').text 
            cve = tag.find('cve').text if tag.find('cve') is not None else None
            cvss = tag.find('cvss3_base_score').text if tag.find('cvss3_base_score') is not None else None   
            if severity >= 1:    
                nessus_matrix.append([machine_name,port,netbios,os,ip,pluginID,severity,pluginName,cve,cvss,synopsis])
                nessus_dict[machine_name][port]= { 'netbios':netbios,'ip':ip,'os':os,'pluginID':pluginID,'pluginName':pluginName,'severity':severity,'cve':cve,'cvss':cvss,'synopsis':synopsis }        
                #print(machine_name,"\t",port,"\t",netbios,"\t",os,"\t",ip,"\t",pluginID,"\t",severity,"\t",pluginName,"\t",cve,"\t",cvss,'\t',synopsis)
        

    result['changed'] = True
    result['output'] = nessus_dict

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
 
