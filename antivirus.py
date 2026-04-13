from pathlib import *
import requests
import time


def post_file(filepath, api_key):
    if(filepath.stat().st_size < 34359738368):
        url = "https://www.virustotal.com/api/v3/files"
    else:
        headers = {
        "accept": "application/json",
        "x-apikey": "91ad757684956a07f1d08f6962fb84698cc6146314b353f5a6ac485ca0c4fe62"
        }
        getuploadurl = requests.get("https://www.virustotal.com/api/v3/files/upload_url", headers=headers) 
        url = getuploadurl.json()['data']

    filepath = str(filepath)
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
        # changes will be made here
        print(postfile.json())

def get_res(id, headers):
    getresult = requests.get(f"https://www.virustotal.com/api/v3/analyses/{id}", headers=headers)
    status = getresult.json()['data']['attributes']['status']
    while(status != "completed"):
        getresult = requests.get(f"https://www.virustotal.com/api/v3/analyses/{id}", headers=headers)
        status = getresult.json()['data']['attributes']['status']
        time.sleep(3)
    if getresult.status_code in [200, 201]:
        print(getresult.json()['data']['attributes']['stats'])
    else:
        print("Error getting file information:", getresult.status_code)

def allfiles(path, filelist, apikey):
    for itempath in path.iterdir():
        if itempath.is_dir():
            allfiles(itempath, filelist, apikey)
        else:
            filelist.append(itempath.name)
            print(f"Scanning {itempath.name}...")
            post_file(itempath, apikey)

def scan(path, apikey):
    contents = []
    allfiles(path, contents, apikey)
    print(f"Scan completed! \n Scanned: {contents}")


path = Path(input("Enter folder path: "))
apikey = input("Enter api key: ")
scan(path, apikey)