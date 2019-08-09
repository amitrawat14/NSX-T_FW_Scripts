import requests, re, getpass
import requests.packages
import urllib3
import json,csv
from key import *
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


#This script provide comment/tag for specific section
##########################MAIN##############################



##print ('\n\nThis program provide details about specific section in the NSX Firewall. Please enter the section name with case sensitive.\n\n')
##NSX_IP = '''

print(
    '''
Kindly select the NSX Manager IP and Enter
lnp6p9nsxmgr01 - 10.28.57.150
nj4p9nsxmgr01 - 10.197.35.150
ric1p9nsxmgr01 - 10.198.35.150
lon6p9nsxmgr01 - 10.234.35.150
'''
    )
##print (NSX_IP)
##
nsxmanager = input("Please input the nsx manager ip or fqdn: ")


#nsxmanager = '10.28.57.150'
#username = input("Enter username: ")
username = 'admin'
password = password
headers = {'content-type': 'application/json'}



##### Above code block in function nsx_dict_fun & json_nsx_data will be replaced with Below Code..

def nsxSectionData(nsxmanager):  
    url = 'https://'+nsxmanager+'/api/v1/firewall/sections'
    r = requests.get(url=url,headers=headers,auth=(username,password),verify=False)
    data = r.json()
    return data
Sections_Data = nsxSectionData(nsxmanager)

def sectionDictBuild(Sections_Data):
    sectionDict_build = {}
    for item in (Sections_Data['results']):
        sectionDict_build[item['display_name'].upper()] = item['id']
    return sectionDict_build

sectionDict = sectionDictBuild(Sections_Data)  

#######################




## Function take input for section and give all the raw data of selected section fw rules.
def sectionRuleFunc(sectionDict):
    print(sectionDict.keys())
    sectionChoice = input(" \n\n Enter Section name from the above menu i.e 'PDT.SAP.PROD':")
    if sectionChoice.lower() or sectionChoice.upper() or sectionChoice.Title:
        sectionChoice = sectionChoice.upper()
    #sectionChoice = sectionChoice.lower() or sectionChoice.upper()
    #print(sectionChoice)
   #sectionChoice = 'WINDOWS'
    try:
        if sectionChoice in sectionDict.keys():
            #print (type(sectionChoice))
            #print(sectionChoice)
            sectionID = sectionDict[sectionChoice]
            print (f"you have entered {sectionChoice} and ID is {sectionID}")
            url = 'https://'+nsxmanager+'/api/v1/firewall/sections/'+sectionID+'/rules'
            sectionRule = requests.get(url=url,headers=headers,auth=(username,password),verify=False)
            sectionRule = sectionRule.json()
            return sectionRule,sectionChoice
        else:
            print("Section Not Found, Please Enter Section value correctly")
    except(UnboundLocalError):
       print("Enter Section Value from the above list only")
            #print("Section Not Found")
   

sectionRuleData,sectionChoice = sectionRuleFunc(sectionDict)


## Source/Destination/Service Mapper
def srvFinder(item,srvlist):
    if 'services' in item:
        for n1,x in enumerate(item['services']):
            if 'target_display_name' in x:
                srvlist.append(x['target_display_name'])
            elif 'service' in x:
                srvlist.append(x['service']['destination_ports'])
    else:
        srvlist.append("ANY")
    return srvlist


def srcDstFind(item,obj,addr):
    #print(item)
    try:
        for i in item[obj]:
            addr.append(i['target_display_name'])
    except:
        addr.append('ANY')
    return addr


def ruleFinder(sectionRuleData,src="ANY",dst="ANY"):
    #dstlist = []
    print ("="*125)
    print (f"\nTotal Number of Rules in the {sectionChoice} are {len(sectionRuleData['results'])}\n")
    print ("="*125)
    for rules in sectionRuleData['results']:
        dst = srcDstFind(item=rules,obj='destinations',addr=[])
        src = srcDstFind(item=rules,obj='sources',addr=[])
        service = srvFinder(item=rules,srvlist=[])
        print (f'Sources == {src} || destination == {dst} || Services == {service}')
    print ("="*125)    

ruleFinder(sectionRuleData)

while True:
    print("\n\nType exit or quit to leave the program or press enter to find the section details")
    choice  = input()
    #print (choice)
    choiceList = ['exit','EXIT','quit','QUIT','no','NO']
    if choice in choiceList:
        break
    else:
        sectionRuleData,sectionChoice = sectionRuleFunc(sectionDict)
        ruleFinder(sectionRuleData)
        
    































