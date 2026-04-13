from pathlib import *
import requests
import time


def post_file(filepath, api_key):
    filepath = str(filepath)
    url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "x-apikey": api_key
    }
    with open(filepath, "rb") as f:
        files = {
            "file": (filepath, f)
        }
        postfile = requests.post(url, headers=headers, files=files)

    if postfile.status_code in [200, 201]:
        id = postfile.json()['data']['id']
        get_res(id, headers)
        
    elif postfile.status_code == 409:
        print(post_file.json())

def get_res(id, headers):
    getfile = requests.get(f"https://www.virustotal.com/api/v3/analyses/{id}", headers=headers)
    status = getfile.json()['data']['attributes']['status']
    while(status != "completed"):
        getfile = requests.get(f"https://www.virustotal.com/api/v3/analyses/{id}", headers=headers)
        status = getfile.json()['data']['attributes']['status']
        time.sleep(3)
    if getfile.status_code in [200, 201]:
        print(getfile.json()['data']['attributes']['stats'])
    else:
        print("Error getting file information:", getfile.status_code)

def allfiles(path, filelist):
    for itempath in path.iterdir():
        if itempath.is_dir():
            allfiles(itempath, filelist)
        else:
            filelist.append(itempath)
            print(f"Scanning {itempath.name}...")
            post_file(itempath, "91ad757684956a07f1d08f6962fb84698cc6146314b353f5a6ac485ca0c4fe62")

def scan(path):
    contents = []
    allfiles(path, contents)
    return contents


path = Path(input("Enter folder path: "))
print(scan(path))