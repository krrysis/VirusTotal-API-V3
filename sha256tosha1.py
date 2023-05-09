import requests
import json
import re
import csv

#opens file with sha256 values
with open('ioc.csv', newline='') as f:
    reader = csv.reader(f)
    ioclist = [item for sublist in reader for item in sublist]
#blank output list which will be used to write to output csv file
outputlist=[]

#loop to get sha1 from sha256 into a list
for i in range(len(ioclist)):
    x=ioclist[i]
    #print(x)
    url = "https://www.virustotal.com/api/v3/search?query="+x
    headers = {
            "accept": "application/json",
            "x-apikey": "1664211c7353df910d72ad121809dd94feb632ad198c361bfc53c6c640f8d540"
        }
    response = requests.get(url, headers=headers)
    data=response.json()
    #print(data)
    pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    url_pattern = r"(https?://)?(www\.)?([a-zA-Z0-9]+(-?[a-zA-Z0-9])*\.)+[a-z]{2,}(/[\w\-]*)*"
    regex = re.compile(pattern)
    regexurl = re.compile(url_pattern)
    
    if len(data["data"]) > 0:
        Sha1=("SHA1:", data["data"][0]["attributes"]["sha1"])
        outputlist.append(Sha1[-1])
    else:
        pass
    #print(outputlist)
    #print(data)
    

#this will write outputlist to csv file
with open('sha1.csv', 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerows([[value] for value in outputlist])