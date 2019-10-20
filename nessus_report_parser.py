import xmltodict
import xml.etree.ElementTree as ET


with open('./842.nessus') as fd:
    doc = xmltodict.parse(fd.read())
        
root = ET.parse('./842.nessus').getroot()

for tag in root.findall('Report/ReportHost'):
    machine_name = tag.get('name')
    tags = root.findall('Report/ReportHost/HostProperties/tag')
    os = [i.text for i in tags if i.get('name') == 'operating-system']
    ip = [i.text for i in tags if i.get('name') == 'host-ip']
    netbios = [i.text for i in tags if i.get('name') == 'netbios-name']
    for tag in root.findall('Report/ReportHost/ReportItem'):
        pluginID = tag.get('pluginID')
        severity = int(tag.get('severity'))
        pluginName = tag.get('pluginName')  #tab is a dictionary so you can use tag['severity'] 
        description = tag.find('description').text
        synopsis = tag.find('synopsis').text 
        cve = tag.find('cve').text if tag.find('cve') is not None else None
        cvss = tag.find('cvss3_base_score').text if tag.find('cvss3_base_score') is not None else None   
        if severity >= 2:
            print(machine_name,"\t",netbios,"\t",os,"\t",ip,"\t",pluginID,"\t",severity,"\t",pluginName,"\t",cve,"\t",cvss,)
            print(synopsis)
           
