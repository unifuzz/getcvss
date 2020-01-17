# getcvss [![Build Status](https://travis-ci.org/UNIFUZZ/getcvss.svg?branch=master)](https://travis-ci.org/UNIFUZZ/getcvss)
Get CVSS data from NVD data feed.

Use [travis-ci](https://travis-ci.org/UNIFUZZ/getcvss) to auto trigger update per day.

## Download

You can download current cvss data here: [https://p.py3.io/cvss.csv.zip](https://p.py3.io/cvss.csv.zip)

## Format

`CVE ID, CWEs, CVSSv3_score, CVSSv2_score, vector_v3, vector_v2`

CWEs are concatenated by '/', example: `CWE-400/CWE-835`

Missing CVSS scores are denoted by -1.

Sorted by CVE ID ascending order.

## Take a quick view:

```
CVE-2010-3624,CWE-20,-1,9.3,,AV:N/AC:M/Au:N/C:C/I:C/A:C
CVE-2010-3630,NVD-CWE-noinfo,-1,9.3,,AV:N/AC:M/Au:N/C:C/I:C/A:C
CVE-2011-1474,CWE-400/CWE-835,5.5,4.9,CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H,AV:L/AC:L/Au:N/C:N/I:N/A:C
CVE-2013-5620,,-1,-1,,
CVE-2020-7108,,-1,-1,,
```