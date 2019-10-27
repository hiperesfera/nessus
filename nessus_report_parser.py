# Nessus exports the scan results in SCAP format. This is when using its API through pyTenable python module
# sc.scan_instances.export_scan(scan_id), file_object)
# the result of above method is a ZIP file containg the Nessus report in SCAP (XML) format


import xml.etree.ElementTree as ET

    
    
root = ET.parse('./842.nessus_v2').getroot()

nessus_dict = {}
nessus_matrix = []


for host in root.findall('Report/ReportHost'):
    
    machine_name = host.get('name')
    nessus_dict = { machine_name:{} } 
    
    
    for tag in host.find('HostProperties').iter('tag'):
        if tag.attrib['name'] == 'operating-system':
            os = tag.text 
            print(os)
        if tag.attrib['name'] == 'netbios-name':
            netbios = tag.text 
            print(netbios)
        if tag.attrib['name'] == 'host-ip':
            ip = tag.text 
            print(ip)
            
    
    for reportItem in host.iter('ReportItem'):
        port = int(reportItem.get('port'))
        pluginId = int(reportItem.get('pluginID'))
        pluginName = reportItem.get('pluginName')
        synopsis = reportItem.get('synopsis')
        severity = int(reportItem.get('severity'))
        cve = tag.find('cve').text if tag.find('cve') is not None else None
        cvss = tag.find('cvss3_base_score').text if tag.find('cvss3_base_score') is not None else None 
        
        if severity >= 2:
            nessus_matrix.append([machine_name,port,netbios,os,ip,pluginId,severity,pluginName,cve,cvss,synopsis])
            nessus_dict[machine_name][port]= { 'netbios':netbios,'ip':ip,'os':os,'pluginId':pluginId,'pluginName':pluginName,'severity':severity,'cve':cve,'cvss':cvss,'synopsis':synopsis }
            
            print(machine_name,"\t",port,"\t",netbios,"\t",os,"\t",ip,"\t",pluginId,"\t",severity,"\t",pluginName,"\t",cve,"\t",cvss,'\t',synopsis)
        
    
    print("----------------------------------")
    
           
