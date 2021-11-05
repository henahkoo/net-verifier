## Written by Henah Koo

## Translator .json -> .gns3
## Input: json file from specification.py
## Output: gns3 file for gns3 emulation startup

import os
import string
import random
import json

def uidgen(size):
    return ''.join(random.SystemRandom().choice(string.ascii_lowercase + string.digits) for _ in range(size))

def create_base_file(templatejson, resultfile):
    template = open(templatejson, "r")
    project_name = "translator_test"
    project_id = uidgen(8)+'-'+uidgen(4)+'-'+uidgen(4)+'-'+uidgen(4)+'-'+uidgen(12)
    open(resultfile,"a+")

    with open(templatejson, 'r') as file :
        filedata = file.read()

    filedata = filedata.replace('*name*', project_name)
    filedata = filedata.replace('*id*', str(project_id))

    with open(resultfile, 'w') as file:
        file.write(filedata)
    template.close()

def add_drawings(templatejson, resultfile, unodes):
    temptarget = open('tempresult2.gns3', 'w+')

    with open(templatejson, 'r') as file :
        filedata = file.read()
        copy_filedata = filedata

        for i in range (unodes):
            drawing_id = uidgen(8)+'-'+uidgen(4)+'-'+uidgen(4)+'-'+uidgen(4)+'-'+uidgen(12)
            filedata = filedata.replace('*id*', drawing_id)
            filedata = filedata.replace('*x*', str(20))
            filedata = filedata.replace('*y*', str(30))
            # print(str(i)+" "+ copy_filedata)
            temptarget.write(filedata)
            if (i!=unodes-1):
                temptarget.write(',\n')
            filedata = copy_filedata
    
    # tempresultfile -> resultfile
    temptarget.seek(0)
    temp = temptarget.read()
    temptarget.close()

    file = open(resultfile, 'r+')
    result = file.read()
    result = result.replace('*drawings*', temp)
    file.seek(0)
    file.write(result)
    file.close()

# def add_links():

# def add_nodes():


def unique_nodes():
    with open('1025out2.json') as f:
        data = json.load(f)
    # unique nodes
    ur = data["topology"]["reachable_nodes"]["py/set"]
    # unique names
    un = list(set([s.split(":")[0] for s in ur]))
    return len(un)
	# print(un)


def main():
    project_name = "translator_test"
    project_id = uidgen(8)+'-'+uidgen(4)+'-'+uidgen(4)+'-'+uidgen(4)+'-'+uidgen(12)    
    templatejson = "./template.json"
    path = "/Users/henah/Documents/2021/Fall/Heimdall/net-verifier/"
    out = open(os.path.join(path, "result.gns3"), "w")

    create_base_file(templatejson, os.path.join(path, "result.gns3"))
    add_drawings("./template_drawings.json", os.path.join(path, "result.gns3"), unique_nodes())
    print("Hi")


if __name__ == '__main__':
	main()

