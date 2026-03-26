from pathlib import *

def allfiles(path, filelist):
    for itempath in path.iterdir():
        if itempath.is_dir():

            allfiles(itempath, filelist)
        filelist.append(itempath.name)

def scan(path):
    contents = []
    allfiles(path, contents)
    return contents


path = Path(input("Enter folder path: "))
print(scan(path))