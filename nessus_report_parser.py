# Nessus exports the scan results in SCAP format. This is when using its API through pyTenable python module
# sc.scan_instances.export_scan(scan_id), file_object)
# the result of above method is a ZIP file containg the Nessus report in SCAP (XML) format

#!/usr/local/lib/python2.7

import xml.etree.ElementTree as ET
import pandas as pd
import matplotlib.pyplot as plt
import re



report_location = './842.nessus_v2'    
    
root = ET.parse(report_location).getroot()

nessus_dict = {}
nessus_matrix = []
nessus_matrix_cols = ['machine_name','host_fqdn','port','netbios','os','ip','host_rdns','plugin_publication_date','plugin_publication_year','plugin_publication_month','pluginFamily','pluginId','severity','pluginName','solution','cve','cvss_base_score','cvss2_base_score','cvss3_base_score','synopsis','plugin_output']


os = None
netbios = None
ip = None
host_rdns = None
host_fqdn = None


for host in root.findall('Report/ReportHost'):
    
    machine_name = host.get('name')
    nessus_dict = { machine_name:{} } 
    
    
    for tag in host.findall('HostProperties/tag'):
        if tag.get('name') == 'operating-system':
            os = tag.text
  
        if tag.get('name') == 'netbios-name':
            netbios = tag.text
  
        if tag.get('name') == 'host-ip':
            ip = tag.text
            
        if tag.get('name') == 'host-rdns':
            host_rdns = tag.text
         
        if tag.get('name') == 'host-fqdn':
            host_fqdn = tag.text
            
                
            
    for reportItem in host.iter('ReportItem'):
        
        port = int(reportItem.get('port'))
        pluginId = int(reportItem.get('pluginID'))
        pluginName = reportItem.get('pluginName')
        synopsis = reportItem.get('synopsis')
        severity = int(reportItem.get('severity'))
        pluginFamily = reportItem.get('pluginFamily')
        
        cve = reportItem.find('cve').text if reportItem.find('cve') is not None else None
        cvss_base_score = reportItem.find('cvss_base_score').text if reportItem.find('cvss_base_score') is not None else None 
        cvss2_base_score = reportItem.find('cvss2_base_score').text if reportItem.find('cvss2_base_score') is not None else None 
        cvss3_base_score = reportItem.find('cvss3_base_score').text if reportItem.find('cvss3_base_score') is not None else None 
        synopsis = reportItem.find('synopsis').text if reportItem.find('synopsis') is not None else None
        solution = reportItem.find('solution').text if reportItem.find('solution') is not None else None
        plugin_output = reportItem.find('plugin_output').text if reportItem.find('plugin_output') is not None else None
        plugin_publication_date = reportItem.find('plugin_publication_date').text if reportItem.find('plugin_publication_date') is not None else None
        plugin_publication_year = re.search('(\d{4})/(\d{2})',plugin_publication_date).group(1)
        plugin_publication_month = re.search('(\d{4})/(\d{2})',plugin_publication_date).group(2)
   
        if severity >= 1:
            nessus_matrix.append([machine_name,host_fqdn,port,netbios,os,ip,host_rdns,plugin_publication_date,plugin_publication_year,plugin_publication_month,pluginFamily,pluginId,severity,pluginName,solution,cve,cvss_base_score,cvss2_base_score,cvss3_base_score,synopsis,plugin_output])
            #nessus_dict[machine_name][port]= { 'netbios':netbios,'ip':ip,'os':os,'pluginId':pluginId,'pluginName':pluginName,'severity':severity,'cve':cve,'cvss':cvss,'synopsis':synopsis }
            
            #print(nessus_dict)
            #print(machine_name,"\t",port,"\t",netbios,"\t",os,"\t",ip,"\t",pluginId,"\t",severity,"\t",pluginName,"\t",cve,"\t",cvss,'\t',synopsis)
        else:
            nessus_matrix.append([None]*11)
    
    # create a dataframe. This is useful if we need to search/analyse the data later.
    df = pd.DataFrame(nessus_matrix, columns = nessus_matrix_cols)
    df.dropna(axis=0, how='all', thresh=None, subset=None, inplace=True)
    df.reset_index(inplace=True)
    df.to_excel("output.xlsx")
    
    print(df)
    



    
           
