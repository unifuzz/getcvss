import requests
sess = requests.session()
import gzip
import json
import time
import os

def downloadyear(year):
    print("fetching year", year)
    url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz".format(year=year)
    req = sess.get(url, stream=True)
    return gzip.open(req.raw).read().decode()

def getdata(year):
    # {"id": ["CWE1/CWE2", "CVSSV3 score", "CVSSV2 score", "vector V3", "vector V2"]}
    # example: "CVE-2011-1474": ["CWE-400/CWE-835", 5.5, 4.9, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", "AV:L/AC:L/Au:N/C:N/I:N/A:C"]
    data = json.loads(downloadyear(year))
    res = {}
    for item in data["CVE_Items"]:
        id = item["cve"]["CVE_data_meta"]["ID"]
        cwes = [i["value"] for i in item["cve"]["problemtype"]["problemtype_data"][0]["description"]]
        cwe = "/".join(cwes)
        try:
            cvssv3_score, vector_v3 = item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"], item["impact"]["baseMetricV3"]["cvssV3"]["vectorString"]
        except:
            cvssv3_score, vector_v3 = -1, ""
        try:
            cvssv2_score, vector_v2 = item["impact"]["baseMetricV2"]["cvssV2"]["baseScore"], item["impact"]["baseMetricV2"]["cvssV2"]["vectorString"]
        except:
            cvssv2_score, vector_v2 = -1, ""
        res[id] = [cwe, cvssv3_score, cvssv2_score, vector_v3, vector_v2]
    return res

def fullupdate():
    res = {}
    currentyear = int(time.strftime("%Y"))
    for year in range(2002, currentyear+1):
        res.update(getdata(year))
    res.update(getdata("recent"))
    return res

def writetofile(filepath, data):
    d = sorted(data.items(), key=lambda i:(int(i[0].split("-")[1]),int(i[0].split("-")[2])))
    with open(filepath, "w") as fp:
        for id, (cwe, cvssv3_score, cvssv2_score, vector_v3, vector_v2) in d:
            fp.write(",".join([str(i) for i in [id, cwe, cvssv3_score, cvssv2_score, vector_v3, vector_v2]])+"\n")

def readfromfile(filepath):
    data = {}
    for _line in open(filepath):
        id, cwe, cvssv3_score, cvssv2_score, vector_v3, vector_v2 = _line.strip().split(",")
        data[id] = [cwe, float(cvssv3_score), float(cvssv2_score), vector_v3, vector_v2]
    return data

if __name__ == "__main__":
    #print(getdata("recent"))
    #print(os.path.getmtime("/tmp/cvssdata/data.csv"), time.time()-os.path.getmtime("/tmp/cvssdata/data.csv"))
    data = fullupdate()
    writetofile("/tmp/cvssdata/data.csv", data)
    # TODO: add meta data comparation to avoid full update