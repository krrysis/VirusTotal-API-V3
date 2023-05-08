import requests
import json
import re
import csv

with open('ioc.csv', newline='') as f:
    reader = csv.reader(f)
    data = [item for sublist in reader for item in sublist]

for i in range(len(data)):
    x=data[i]
    url = "https://www.virustotal.com/api/v3/search?query="+x
    headers = {
            "accept": "application/json",
            "x-apikey": "your api key goes here"
        }
    response = requests.get(url, headers=headers)
    data=response.json()

    response = requests.get(url, headers=headers)
    data=response.json()
    pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    url_pattern = r"(https?://)?(www\.)?([a-zA-Z0-9]+(-?[a-zA-Z0-9])*\.)+[a-z]{2,}(/[\w\-]*)*"
    regex = re.compile(pattern)
    regexurl = re.compile(url_pattern)
    
    if len(data["data"]) > 0:
        Sha1=("SHA1:", data["data"][0]["attributes"]["sha1"])
        