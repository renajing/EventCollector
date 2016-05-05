#!/usr/bin/python

import subprocess
import re
import urllib
import urllib2
import socket
import time
import httplib
import requests
import json

# splunk indexer object
class SplunkProxy:
    __url = 'http://localhost:8088/services/collector/event'
    __headers = {'Authorization': '',}
    __cmd = "POST"
    __events = None

    def __init__( self, server, port ):
        self.__url = "http://" + server + ":" + str(port) + "/services/collector/event"

    def setHeader( self, name, value ):
        self.__headers[name] = value

    def setTestMode( self ):
        self.setHeader('Authorization', '')

    def getRESTpoint(self):
        return self.__url

    def addEvent( self, data ):
        print "adding event: ", data
        if (self.__events):
            self.__events = self.__events + data
        else:
            self.__events = data
        print "Events: ", self.__events

    # send request
    def post( self, data ):
        print "sending ..."
        print self.__url
        print self.__headers
        print data
        handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        req = urllib2.Request(self.__url, data, self.__headers)
        req.get_method = lambda: self.__cmd

        try:
            connection = opener.open(req)
        except urllib2.HTTPError, e:
            connection = e
        print "Response: ", connection.code

    def post( self ):
        if (self.__events):
            print "sending all ..."
            print self.__url
            print self.__headers
            print self.__events

    
            handler = urllib2.HTTPHandler()
            opener = urllib2.build_opener(handler)

            headers = {
                'Authorization': '',
            }

	    print "sending"	
            try:
                r = requests.post(self.__url, headers=headers, data=self.__events)
                print  r.status_code
            except:
                print "fail"

            if(r.status_code==400):
                exit()


# event builder
class EventBuilder:
    __fields = []
    __hostname = "localhost"
    __timestamp = 0
    __jsondata = ""
    __index = None
    __sourcetype = "testdata"

    def __init__( self, fields ):
        self.__fields = fields
        self.__hostname = socket.gethostname()
        self.__timestamp = time.time()
        self.reset()

    def __init__( self, index, sourcetype, fields ):
        self.__index = index
        self.__sourcetype = sourcetype
        self.__fields = fields
        self.__hostname = socket.gethostname()
        self.__timestamp = time.time()
        self.reset()

    def reset( self ):
        if (self.__index):
            self.__jsondata = '{"source": "pycode", "index": "' + self.__index + '", "sourcetype": "' + self.__sourcetype + '", "host": "' + self.__hostname + '", "time": "' + str(self.__timestamp) + '"'
        else:
            self.__jsondata = '{"source": "pycode", "sourcetype": "' + self.__sourcetype + '", "host": "' + self.__hostname + '", "time": "' + str(self.__timestamp) + '"'

    def reinit( self, index, sourcetype ):
        self.setIndex(index)
        self.setSourcetype(sourcetype)
        self.reset()

    def setIndex(self, index):
        self.__index = index;

    def setSourcetype(self, sourcetype):
        self.__sourcetype = sourcetype;

    def getHostname(self):
        return self.__hostname

    def getTimestamp(self):
        return self.__timestamp

    # build json event
    def buildEvent(self, data):
        print "Build event with fields:", self.__fields
        event = '"event": {'
        totalItems = len(data)
        if (len(self.__fields) != totalItems):
            print "ERROR: unexpected number of data items:", totalItems
            event = '"event": "CANNOT EXTRACT"'
            return event

        sep = ""
        for i in range(totalItems):
            event = event + sep + '"' + str(self.__fields[i]) + '": "' + str(data[i]) + '"'
            print "%s: %s" % (self.__fields[i], data[i])
            sep = ", "

        event = event + "}"
        print "Built event: ", event
        self.__jsondata = self.__jsondata + ', ' + event

    def getJSONdata(self):
        data = self.__jsondata + "}"
        return data

############################################################################
# Splunk proxy instance
splunk = SplunkProxy("localhost", "8088")
index = 'test'
runningBuild = '0'


# Get vmstat data

sourcetype = 'vmstat'

# vmstat fields
vm = subprocess.Popen("systeminfo|findstr Memory", shell=True, stdout=subprocess.PIPE).communicate()[0]
print vm

# Process vm_stat
vmLines = vm.split('\r\n')
sep = re.compile(':[\s]+')
vmStats = {}
allFields = []
allEntries = []


for row in vmLines:
	if row != "":
		splitRow = row.split(": ")
		field = re.findall("[\a-z :]+:", row)[0]
		entry = re.findall("[0-9,]+[ A-Z]+", row)[0]
		field = field[:-1]
		allFields.append(field)
		allEntries.append(entry)

print allFields
print allEntries


builder = EventBuilder(index, sourcetype, allFields)
builder.buildEvent(allEntries)
print "Built event is "
print builder.getJSONdata()

splunk.addEvent( builder.getJSONdata() )



##################################################################

#Process diskstat info

sourcetype = "diskstat"
fields = ('Free', 'Total', 'Available' )
diskstat = subprocess.Popen("fsutil volume diskfree C:", shell=True, stdout=subprocess.PIPE).communicate()[0]
print diskstat

diskstatLines = diskstat.split('\r\n')
sep = re.compile(':[\s]+')
vmStats = {}
allFields = []
allEntries = []


for row in diskstatLines:
	if row != "":
		splitRow = row.split(": ")
		field = re.findall("[\a-z :]+:", row)[0]
		entry = re.findall("[0-9,]+[ A-Z]*", row)[0]
		field = str(field)
		field = field[:-1]
		allFields.append(field)
		allEntries.append(entry)

print allFields
print allEntries


builder = EventBuilder(index, sourcetype, fields)
builder.buildEvent(allEntries)
print "Built event is "
print builder.getJSONdata()

splunk.addEvent( builder.getJSONdata() )


###################################################################

#Process appstat info

sourcetype = "appstat"
fields = ('Image Name', 'PID', 'Session Name', 'Session', 'Mem Usage', 'Status','User Name','CPU Time',
'Window Title')

appstat = subprocess.Popen("tasklist -v", shell=True, stdout=subprocess.PIPE).communicate()[0]

appstatLines = appstat.split('\r\n')
sep = re.compile(':[\s]+')


for i in range(3,len(appstatLines)):

        line = appstatLines[i]
	allEntries = []

        #create delimiter for Image Name 
        delim = re.compile(".*?(?=\s{2})")
        #extract the field from regex
        entry = re.search(delim, line).group(0)
        #split into a new line without delimiter 
        line = delim.split(line,1)[1]
        #escape \ characters
        entry = json.dumps(entry, encoding="utf8")
        entry = entry.replace('\"', " ")
        allEntries.append(str(entry))      

        #create delimiter for PID
        delim = re.compile("[0-9]+")
        entry = re.search(delim, line).group(0)
        line = delim.split(line,1)[1]
        allEntries.append(entry)
        
        #create delimiter for Session Name
        delim = re.compile("[^\s].*?(?=\s{2})")
        entry = re.search(delim, line).group(0)
        line = delim.split(line,1)[1]
        allEntries.append(str(entry))

        #create delimiter for Session Number 
        delim = re.compile("[0-9]+")
        entry = re.search(delim, line).group(0)
        line = delim.split(line,1)[1]
        allEntries.append(str(entry))

        #create delimiter for Mem Usage
        delim = re.compile("[0-9,]+\s\w+\s")
        entry = re.search(delim, line).group(0)
        line = delim.split(line,1)[1]
        allEntries.append(str(entry))

        #create delimiter for Status 
        delim = re.compile(".*?(?=\s{2})")
        entry = re.search(delim, line).group(0)
        line = delim.split(line,1)[1]
        allEntries.append(str(entry))

        #create delimiter for User Name (regex is first nonspace char to two consecutive spaces)
        delim = re.compile("[^\s].*?(?=\s{2})")
        entry = re.search(delim, line).group(0)
        line = delim.split(line,1)[1]
        entry = str(entry)
        entry = json.dumps(entry, encoding="utf8")
        entry = entry.replace('\"', " ")
        allEntries.append(entry)

        #create delimiter for time 
        delim = re.compile("[0-9.]+")
        entry = re.search(delim, line).group(0)
        line = delim.split(line,1)[1]
        allEntries.append(str(entry))

        #create delimiter for Window Title 
        delim = re.compile("[^\s].*?(?=\s{2})")
        entry = re.search(delim, line).group(0)
        line = delim.split(line,1)[1]
        entry = json.dumps(entry, encoding="utf8")
        entry = entry.replace('\"', " ")
        allEntries.append(str(entry))


        builder = EventBuilder(index, sourcetype, fields)
        builder.buildEvent(allEntries)
        print "Built event is "
        print builder.getJSONdata()
        splunk.addEvent( builder.getJSONdata() )

        splunk.post()
	

# Send data to splunk.

splunk.post()
exit()
