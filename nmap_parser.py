'''
from arpeggio import Optional, ZeroOrMore, OneOrMore, EOF
from arpeggio import RegExMatch as _

def DigNum:	return

def OSOut:			return
def PortsClosedFlag:return 'All 1000 scanned ports on ', IP, ' are closed'
def PortsFlag:		return 'PORT     STATE SERVICE'
def Ports:			return 
def IPFlag:			return 'Nmap scan report for '
def IP:				return _(r'\d+\.\d+\.\d+\.\d+')
def DeviceOut:		return IPFlag, IP, 
def NmapOut:		return OneOrMore(DeviceOut), EOF
'''

'''
OS details overrides Running, other case is only have Running to go off of
Mac Address's () unless it is unknown
always get Device Type
'''
import re
import json


def parse_nmap(filepath):
    line = None
    jsonDerulo = {}
    with open(filepath) as mf:
        def portParse(myIP, numP):
            for x in range(0, numP):
                line = mf.readline()
                # print("	" + line)
                portNum, state, *servicel = line.split()
                service = ' '.join(servicel)
                jsonDerulo[myIP][portNum] = service
                # print("	" + str(service))

        def OSParse(myIP, firstLine):
            MA = ''
            DT = ''
            R = ''
            OD = ''
            while not firstLine.startswith('Network Distance:'):
                if firstLine.startswith('MAC Address:'):
                    osI1 = re.split('\(|\)', firstLine)
                    # print("		" + str(osI1[-2]))
                    if osI1[-2] != 'Unknown':
                        MA = osI1[-2]
                elif firstLine.startswith('Device type:'):
                    out = firstLine.split(': ')[-1]
                    # print(out)
                    sout = re.split('\||\\n', out)
                    # print("		" + str(sout))
                    DT = sout[:-1]
                elif firstLine.startswith('Running:'):
                    out = firstLine.split(': ')[-1]
                    # print(out)
                    sout = re.split('\\n', out)
                    # print("		" + str(sout))
                    R = sout[:-1]
                elif firstLine.startswith('OS details:'):
                    out = firstLine.split(': ')[-1]
                    # print(out)
                    sout = re.split('\\n', out)
                    # print("		" + str(sout))
                    OD = sout[:-1]
                firstLine = mf.readline()
            # print("--" + str(MA))
            # print("--" + str(DT))
            # print("--" + str(R))
            # print("--" + str(OD))
            OSOut = {}
            if MA != '':
                OSOut['Manufacturing Company'] = MA
            if DT != '':
                OSOut['Device Type'] = DT
            if R != '' and OD == '':
                OSOut['OS Environment'] = R
            if OD != '':
                OSOut['OS Environment'] = OD
            # print(OSOut)
            jsonDerulo[myIP]['OS Info'] = OSOut

        # add to json

        line = mf.readline()
        while line:
            # new device report found
            if line.startswith('Nmap scan report for '):
                *junk, ip = line.split()
                # print(ip)
                jsonDerulo[ip] = {}

                # getting ports
                mf.readline()
                line = mf.readline()
                if not line.startswith('All'):
                    # port num correction
                    numPorts1 = line.split()[2]
                    numPorts2 = line.split()[-3]
                    numPortsf = 1000 - int(numPorts1)
                    if numPorts1 != numPorts2:
                        numPortsf = numPortsf - int(numPorts2)

                    mf.readline()
                    portParse(ip, numPortsf)

                # figuring the OS
                fline = mf.readline()
                # if OS detectable
                if not fline.startswith('Too many'):
                    OSParse(ip, fline)
            line = mf.readline()
        # print(jsonDerulo)

        # Json creation
        json_dump = json.dumps(jsonDerulo, sort_keys=False, indent=4)

        json_file = open('nmap_output.json', 'w')
        json_file.write(json_dump)
        json_file.close()

        return jsonDerulo
