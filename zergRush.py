#!/usr/bin/python
# Virus Total API Integration Script
# Built on VT Test Script from: Adam Meyers ~ CrowdStrike
# Rewirtten / Modified / Personalized: Chris Clark ~ GD Fidelis CyberSecurity
# If things are broken let me know chris@xenosec.org
# No Licence or warranty expressed or implied, use however you wish! 

import json, urllib, urllib2, argparse, hashlib, re, sys, os
from pprint import pprint

class vtAPI():
    def __init__(self):
        self.api = '<--------------PUBLIC-API-KEY-GOES-HERE----->'
        self.base = 'https://www.virustotal.com/vtapi/v2/'
    
    def getReport(self,md5):
        param = {'resource':md5,'apikey':self.api}
        url = self.base + "file/report"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        jdata =  json.loads(result.read())
        return jdata
    
    def rescan(self,md5):
        param = {'resource':md5,'apikey':self.api}
        url = self.base + "file/rescan"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        print "\n\tVirus Total Rescan Initiated for -- " + md5 + " (Requery in 10 Mins)"


# Md5 Function

def checkMD5(checkval):
  if re.match(r"([a-fA-F\d]{32})", checkval) == None:
    md5 = md5sum(checkval)
    return md5.upper()
  else: 
    return checkval.upper()

def md5sum(filename):
  fh = open(filename, 'rb')
  m = hashlib.md5()
  while True:
      data = fh.read(8192)
      if not data:
          break
      m.update(data)
  return m.hexdigest() 
          
def parse(it, md5, verbose, jsondump):
  if it['response_code'] == 0:
    print md5 + " -- Not Found in VT"
    return 0
  print "\n\tResults for MD5: ",it['md5'],"\n\n\tDetected by: ",it['positives'],'/',it['total'],'\n'
  if 'Sophos' in it['scans']:
    print '\tSophos Detection:',it['scans']['Sophos']['result'],'\n'
  if 'Kaspersky' in it['scans']:
    print '\tKaspersky Detection:',it['scans']['Kaspersky']['result'], '\n'
  if 'ESET-NOD32' in it['scans']:
    print '\tESET Detection:',it['scans']['ESET-NOD32']['result'],'\n'

  print '\tScanned on:',it['scan_date']
  
  if jsondump == True:
    jsondumpfile = open("VTDL" + md5 + ".json", "w")
    pprint(it, jsondumpfile)
    jsondumpfile.close()
    print "\n\tJSON Written to File -- " + "VTDL" + md5 + ".json"

  if verbose == True:
    print '\n\tVerbose VirusTotal Information Output:\n'
    for x in it['scans']:
     print '\t', x,'\t' if len(x) < 7 else '','\t' if len(x) < 14 else '','\t',it['scans'][x]['detected'], '\t',it['scans'][x]['result']

def main():
  opt=argparse.ArgumentParser(description="Search and Download from VirusTotal")
  opt.add_argument("Directory", help="Enter the path to the directory")
  opt.add_argument("-s", "--search", action="store_true", help="Search VirusTotal")
  opt.add_argument("-v", "--verbose", action="store_true", dest="verbose", help="Turn on verbosity of VT reports")
  opt.add_argument("-j", "--jsondump", action="store_true",help="Dumps the full VT report to file (VTDLXXX.json)")
  opt.add_argument("-r", "--rescan",action="store_true", help="Force Rescan with Current A/V Definitions")
  if len(sys.argv)<=2:
    opt.print_help()
    sys.exit(1)
  options= opt.parse_args()
  vt=vtAPI()
  for file in os.listdir(options.Directory):
    pathName = os.path.dirname(file)
    fullPathName = os.path.abspath(pathName)
    md5 = checkMD5(fullPathName)
    if options.search or options.jsondump or options.verbose:
      parse(vt.getReport(md5), md5 ,options.verbose, options.jsondump)
    if options.rescan:
      vt.rescan(md5)

if __name__ == '__main__':
	main()
	
#	Works Cited
#	Meyers, Adam and Chris Clark. The large majority of this file is taken from the vtlite.py file from their VirusTotal_API_Tool repository.
#	Lines 9-77, 79-87, and 91-98 are unmodified from the original vtlite.py file. These were retained to maintain basic functionality of 
#	generating MD5 hashes for individual files and running them through the VirusTotal API. The additional optional arguments were also retained
#	as the user will still be allowed to specify the degree of detail in the returned reports for all files. The source repository can be found at
#	https://github.com/Xen0ph0n/VirusTotal_API_Tool. West Point, NY. 29 APR 2018.

#	DiveIntoPython. I used the code present on this website to find the path name and absolute path names of files. This can be seen in lines 8, 89,
#	90, and 91. I imported os, called for the directory path portion of the file within the Directory, and then called for the absolute path of that 
#	directory path portion. This absolute path of the file would then be used as input in the checkMD5 function. The borrowed code can be found at
#	http://www.diveintopython.net/functional_programming/finding_the_path.html within the codeblock of Example 16.3. West Point, NY. 29 APR 2018.
