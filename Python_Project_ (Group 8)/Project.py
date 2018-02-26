import MySQLdb as mdb
from netmiko import ConnectHandler
import netmiko
import ipaddress
import threading
import networkx as nx
import numpy as np
import matplotlib.pyplot as plt 
import os.path
import subprocess
import datetime
import time
import sys
import re
import json
import requests
from requests_toolbelt import MultipartEncoder
import requests
import textile

#Module for output coloring
from colorama import init, deinit, Fore, Style
#Initialize colorama
init()
finalipinformation=[]
maclist=[]
interfacesdescriptionlist=[""]
moduleslist=[""]
connectedrouteslist=[""]
pidslist=[""]
EOX={}
#clearing the outputfiles
open("outputfile.txt","w").close()
open("outputfile2.txt","w").close()
def clear_database():
##Clearing the Database 
	sql_host='localhost'
	sql_database='PythonProject'
	sql_username='root'
	sql_password='root'
	sql_conn=mdb.connect(sql_host,sql_username,sql_password,sql_database)
	cursor=sql_conn.cursor()
	cursor.execute("delete from routers")
	sql_conn.commit()
	sql_conn.close()

#calling the clear database function
	
clear_database()
	
while True:
	try:
		#Prompting user for input
		print Fore.GREEN+"\n# # # # # # # # # # # # # # # # # # # # # # # # # # # #\n"
		iprange_file = raw_input(Fore.GREEN+"# Enter IP Range file name and extension: ")
		#Open user selected file for reading (IP Range.txt file)
		password_file = raw_input(Fore.GREEN+"\n# Enter Password file name and extension: ")
		print Fore.GREEN+ "\n# # # # # # # # # # # # # # # # # # # # # # # # # # # #\n"
		#Open user selected file for reading (IP Range.txt file)
		
		selected_iprange_file = open(iprange_file, 'r')
		selected_password_file = open(password_file, 'r')
		#Starting from the beginning of the file
		selected_iprange_file.seek(0)
		selected_password_file.seek(0)
		#Reading each line (IP address range with subnet) and the password in the file
		ip_list = selected_iprange_file.readlines()
		password_list=selected_password_file.readlines()
		#Closing the file
		selected_iprange_file.close()
		selected_password_file.close()
	except IOError:
		print Fore.RED+ "\n !!! You entered a Wrong File Name Please recheck your input for IP range or Password!!!"
		continue
	else:
		break	
		


def ip_address(ip,netmask):
	#############function to check validty of ip address and subnetmask##########
	iplist=[" "]
	flag=0
	while len(iplist)!=4 or flag!=0:
		iplist=ip.split(".")
		flag=0
		if len(iplist)==4:
			for index in range (len(iplist)):
				testnumber=int(iplist[index])
				if testnumber >255 or testnumber<0:
					flag=flag+1
		else:
			flag=flag+1
		if flag!=0:
			print Fore.RED+" \n!!!!!Invalid IP found in the file, Correct the Problem and Rerun the Program  !!!!!\n"
			break
			sys.exit()
	
	if netmask <=0 or netmask>32:
		print Fore.RED+" \n!!!!!Invalid Netmask found in the file Correct the Problem and Rerun the Program !!!!!\n"
		sys.exit()

def ping_Destination(pingnetworks):
	# Prompt the user to input a network address
	net_addr = unicode(pingnetworks)

	# Create the network
	try:
		ip_net = ipaddress.ip_network(net_addr)
		
	except ValueError:
		print Fore.RED+" \n!!!!!Invalid IP Range found in the file Correct the Problem and Rerun the Program !!!!!\n"
		sys.exit()
		
	# Get all hosts on that network
	all_hosts = list(ip_net.hosts())

	print Fore.YELLOW+"\n !!!!PINGING!!!!\n"
	# For each IP address in the subnet, 
	# run the ping command with subprocess.popen interface
	for i in range(len(all_hosts)):
		output = subprocess.Popen(['ping', '-c', '1', '-w', '2','-q','-n', str(all_hosts[i])], stdout=subprocess.PIPE).communicate()[0]
		if "Destination host unreachable" not in output.decode('utf-8') and  "Request timed out" not in output.decode('utf-8')and "100% packet loss" not in output.decode('utf-8'):
			print(str(all_hosts[i]), "is Online")
			finalipinformation.append((str(all_hosts[i])))

#def sql_connection(command,values):
	
def ssh_connection(sship,sshpassword):
	# starting SSH Connection to devices all what we need is ip and password
		try:
			platform='cisco_ios'
			host=sship
			password=sshpassword
			username='admin'
			device = ConnectHandler(device_type=platform,ip=host,username=username,password=password)
			#time.sleep(2)
			
		except netmiko.ssh_exception.NetMikoTimeoutException:
			print Fore.RED+" \n!!!!!Connection to "+ host +" has been failed !!!"
		except netmiko.ssh_exception.NetMikoAuthenticationException:
			print Fore.RED+" \n!!!!!Unable to authenticate to "+ host+" Check password "
		else:
			print Fore.YELLOW+" \n!!!!!SSH Connection to "+ host+" has been established successfully "
			device.send_command('terminal length 0\n')
			time.sleep(1)
			#output=device.send_command('show interfaces | include bia')
			#macaddressregex=re.search(r".*bia (.*)\).*",output)
			#macaddress=str(macaddressregex.group(1))
			output=device.send_command('show ip interface brief')

			#Removing Managment IPs for the same Device to not Connect to it again from different IP
 
			ipaddresslist=re.findall(r"\d{1,3}\.\d{1,3}.\d{1,3}\.\d{1,3}",output)
			for i in range(len(ipaddresslist)):
				ipaddresslist[i]=str(ipaddresslist[i])
			#print ipaddresslist
			for i in range(len(ipaddresslist)):
	     			for j in range (len(finalipinformation)):
	             			if finalipinformation[j] in ipaddresslist:
	                     			finalipinformation[j]=''
	                    			break
			#print finalipinformation
			selected_output_file=open("outputfile.txt", 'a')
			selected_output_file.seek(0)
			output=device.find_prompt()
			print "\n\nManagment IP : "+host
			print "Password : "+password
			hostname=re.search(r"(.*)>.*",output)
			print "hostname: "+hostname.group(1)
			selected_output_file.writelines("\n\nManagment IP: "+host+"\n"+"Password : "+password+"\n"+"hostname: "+hostname.group(1)+"\n\n\n")
			output=device.send_command('show version | include Version')
			OSversion=re.search(r" Version (.*), ",output)
			print "OS version: "+OSversion.group(1)
			selected_output_file.writelines("OS version: "+OSversion.group(1)+"\n")
			output=device.send_command('show hardware | include Cisco')
			HWversion=re.search(r"(Cisco (.*)) with ",output)
			print "HW version: "+HWversion.group(1)
			selected_output_file.writelines("HW version: "+HWversion.group(1)+"\n")
			output=device.send_command('show interfaces description')
			
			#create a list of all lines in the show interfaces output and then capture the desired values via a regex 1,2,5,6
			list1=str(output).split("\n")
			for i in range(1,len(list1)):
				Interfaces_desc_modules=re.search(r"(\S*)\s+((\S*)\s|(\S*\s\S*))\s+(\S*)\s+(.*)",list1[i])
				interfacesdescriptionlist[0]=interfacesdescriptionlist[0]+"interface name: "+Interfaces_desc_modules.group(1)+" interface status: "+Interfaces_desc_modules.group(2)+" protocol description: "+Interfaces_desc_modules.group(5)+" interface Description: "+Interfaces_desc_modules.group(6)+"\n"
				print "interface name: "+Interfaces_desc_modules.group(1)
				print "interface status: "+Interfaces_desc_modules.group(2)
				print "protocol description: "+Interfaces_desc_modules.group(5)
				print "interface Description: "+Interfaces_desc_modules.group(6)+"\n"
				selected_output_file.writelines("\ninterface name: "+Interfaces_desc_modules.group(1)+"\n"+"\ninterface status: "+Interfaces_desc_modules.group(2)+"\nprotocol description: "+Interfaces_desc_modules.group(5)+"\ninterface Description: "+Interfaces_desc_modules.group(6)+"\n")
			
			output=device.send_command('show inventory')
			list2=str(output).split("\n")
			
			#print list2
			#added list 4 for EOX/EOL support
			list4=list2
			list2=list2[::3]	
			for i in range (len(list2)):
				Modules=re.search(r"NAME: (.*), DESCR: (.*).",list2[i])
				try:
					print "Connected Modules Name and Description: "+Modules.group(1)+" "+Modules.group(2)
					moduleslist[0]=moduleslist[0]+"Connected Modules Name and Description: "+Modules.group(1)+" "+Modules.group(2)+"\n"
					selected_output_file.writelines("Connected Modules Name and Description: "+Modules.group(1)+" "+Modules.group(2)+"\n")
				except AttributeError:
					continue
			list4=list4[1::3]
			
			for i in range (len(list4)):
				
				try:
					if i <len(list4)-1:
						PIDs=re.search(r"PID: (.*) *, V.*",list4[i])
						pid=PIDs.group(1)
						pidslist[0]=pidslist[0]+pid.strip(" ")+","
					else:
						pidslist[0]=pidslist[0]+pid.strip(" ")
				except AttributeError:
					continue	
			#print pidslist	
			#creating dict for routers with PIDs to be used in End of support check 	
			EOX[str(hostname.group(1))]=pidslist[0]
			#All are in one line 
			output=device.send_command('show ip route | include C')
			list3=str(output).split("\n")
			list3=list3[1:]
			for i in range(len(list3)):	
				ConnectedRoutes=re.search(r"C\s+(\S*)\s.*",list3[i])
				connectedrouteslist[0]=connectedrouteslist[0]+ConnectedRoutes.group(1)+" "
			time.sleep(1)
			#send information to mysqlDatabase	
			sql_senddata("Replace into routers(Hostname,IP,Password,OS_Ver,HW_Ver,INTDESCSTAT,Modules,ConnectedRoutes)value(%s,%s,%s,%s,%s,%s,%s,%s)",([hostname.group(1)],[host],[password],[OSversion.group(1)],[HWversion.group(1)],[interfacesdescriptionlist[0]],[moduleslist[0]],[connectedrouteslist[0]]))

			#closing Outputfile and SSH Connection
			selected_output_file.close()
			device.disconnect()
			#Clearing all lists
			pidslist[0]=""
			connectedrouteslist[0]=""
			interfacesdescriptionlist[0]=""
			moduleslist[0]=""
			#print moduleslist
			
			
			
		
	
ip_list=ip_list[0].split(",")		
#print ip_list
#print password_list
for i in range (len(ip_list)):
	### Validity Check for Ips and netmask in the Range.txt file 
	#find where the slash is and send the ip only for validty check
	indexofmask=ip_list[i].find("/")
	ip_address(ip_list[i][:indexofmask],int(ip_list[i][indexofmask+1:]))
	if "\n"in ip_list[i]:
		ip_list[i]=ip_list[i].strip("\n")
	ping_Destination(ip_list[i])
	
#checking if it captured any IP or NO, if NO no need to continue the program
if finalipinformation==[]:
	print Fore.RED+" \n!!!!!Exiting the Program NO IP was Found......."
	sys.exit()

def sql_senddata(commands,values):
	sql_host='localhost'
	sql_database='PythonProject'
	sql_username='root'
	sql_password='root'
	sql_conn=mdb.connect(sql_host,sql_username,sql_password,sql_database)
	cursor=sql_conn.cursor()
	cursor.execute(commands,values)
	sql_conn.commit()
	sql_conn.close()
	
#print finalipinformation


#print finalipinformation
for i in range(len(finalipinformation)):
	for j in range (len(password_list)):
		password_list[j]=password_list[j].strip("\r\n")
		
		if finalipinformation[i] != '':
			ssh_connection(finalipinformation[i],(password_list[j]))
			#print finalipinformation	
		
		

	


def draw_the_topolgy():
	sql_host='localhost'
	sql_database='PythonProject'
	sql_username='root'
	sql_password='root'
	sql_conn=mdb.connect(sql_host,sql_username,sql_password,sql_database)
	cursor=sql_conn.cursor()
	sql_conn.commit()
	cursor.execute("select ConnectedRoutes from routers")
	connectedroutesoutput=cursor.fetchall()
	cursor.execute("select hostname from routers")
	hostnameoutput=cursor.fetchall()
	connectedrouteslist=[]
	hostnamelist=[]
	commonrouteslist=[]
	connectedroutesdict={}
	G=nx.Graph()
	for i in range( len(hostnameoutput)):
		hostnamelist.append(hostnameoutput[i][0])
 
	nodes=range(0,len(hostnamelist))
  
	for i in range(len (hostnamelist)):
	
	###drawing edges and comparing routes
    
		connectedrouteslist=connectedroutesoutput[i][0].split(" ")
		connectedrouteslist.remove("")
     
		for j in range (len(connectedroutesoutput)):
				if i != j:
					for k in range(len(connectedrouteslist)):
						if connectedrouteslist[k] in connectedroutesoutput[j][0]:
						
							G.add_edges_from([(j,i)])
							#print "connection between "+hostnamelist[i] +" and "+hostnamelist[j]+" with network address "+ connectedrouteslist[k]
							routes=("%sto%s")%(i,j)
							connectedroutesdict.update({routes:connectedrouteslist[k]})
							if connectedrouteslist[k] not in commonrouteslist:
							#creating a list for further use in drawing
								commonrouteslist.append(connectedrouteslist[k])
							

#nx.draw_spectral(G,edge_color='blue',with_labels=True)

	for i in range(len (hostnamelist)):
	
	###drawing hostnetworks and comparing routes
    
		connectedrouteslist=connectedroutesoutput[i][0].split(" ")
		connectedrouteslist.remove("")
		for j in range(len(connectedrouteslist)):
			if connectedrouteslist[j]not in commonrouteslist:
				nodes.append(len(nodes))
				routes=("%sto%s")%(nodes[-1],i)
				connectedroutesdict.update({routes:connectedrouteslist[j]})
				G.add_node(nodes[-1])
				G.add_edges_from([(i,nodes[-1])])



	 
	nx.draw_shell(G,node_color='Red',edge_color='Black',with_labels=False)
	pos=nx.shell_layout(G)
	for i in  range (len(nodes)):
		for j in range(len(nodes)):
			if  i !=j:
				key=("%sto%s")%(i,j)
			
				if key in connectedroutesdict:
					if i< len(hostnamelist):
							#print key
							plt.text((pos[i][0]+pos[j][0])/2,(pos[i][1]+pos[j][1])/2,connectedroutesdict[key],bbox=dict(facecolor='red',alpha=0.1))
							plt.text(pos[i][0],pos[i][1],hostnamelist[i],fontsize=24)
					else:
						plt.text(pos[i][0],pos[i][1],"LAN network: "+connectedroutesdict[key],bbox=dict(facecolor='red',alpha=0.1))
	plt.savefig("TopolgyGraph.png",format="PNG")
	plt.show()
	sql_conn.close()		 
#print EOX


draw_the_topolgy()

while True:	
	#Checking Connection to the internet 
	output = subprocess.Popen(['ping', '-c', '1', '-w', '2','-q','-n', "8.8.8.8"], stdout=subprocess.PIPE).communicate()[0]
	if "rtt min/avg/max/mdev" in output.decode('utf-8'):
		break
		
	else:
		print Fore.RED+" \n!!!!!Check your Connection to the internet......."
		time.sleep(10)
		continue
		
selected_output_file=open("outputfile2.txt", 'a')
selected_output_file.seek(0)

##Getting Access Token
Client_Secret="kgSRMEzANeHgHbRyxuGJP65e"
Client_ID="k9n8bfgkfxdxv8nuen4ys4pp"
token_rul = 'https://cloudsso.cisco.com/as/token.oauth2?grant_type=client_credentials'
resp = requests.post(token_rul, auth=(Client_ID, Client_Secret)).json()

## Getting Inforamtion about End of life / Support 
for key,value in EOX.iteritems():
	
	url = "https://api.cisco.com/supporttools/eox/rest/5/EOXByProductID/1/"+EOX[key]+"?responseencoding=json"
	auth_t=str(resp[u"access_token"])
	headers = {'authorization': "Bearer " + auth_t,'content-type': "application/json",}
	response=requests.get(url,headers=headers).json()

	print Fore.YELLOW+"\n\nInformation Regarding End of life/ End of Support for Device : "+key+"\n"
	selected_output_file.writelines("\n\n Information Regarding End of life/ End of Support for Device : "+key+"\n")
	for i in range(len(response["EOXRecord"])):
		print Fore.YELLOW+ "Product Description: "+str(response["EOXRecord"][i]["ProductIDDescription"])
		print Fore.YELLOW+"PID : "+str(response["EOXRecord"][i]["EOLProductID"])
		print Fore.YELLOW+"Last Date of Support : "+str(response["EOXRecord"][i]["LastDateOfSupport"]["value"])
		selected_output_file.writelines("\nProduct Description: "+str(response["EOXRecord"][i]["ProductIDDescription"]))
		selected_output_file.writelines("\nPID : "+str(response["EOXRecord"][i]["EOLProductID"]))
		selected_output_file.writelines("\nLast Date of Support : "+str(response["EOXRecord"][i]["LastDateOfSupport"]["value"]))
		
		
	#print response
	time.sleep(2)
selected_output_file.close()

######Converting Outputfiles to HTML Format 

user_file="outputfile.txt"
selected_user_file = open(user_file, 'r')
outputtext=selected_user_file.readlines()
selected_user_file.close()
selected_user_file = open("Topolgyinfo.html", 'w')
html = textile.textile("<h1 style="+"color:Tomato;"+">"+"### Topolgy Information ### </h1></p>")
selected_user_file.writelines(html)
for i in range (len(outputtext)):
	#print outputtext[i]
	pattern=re.search(r"\b(.*:)\s",outputtext[i])
	try:
		try: 
			if "Managment IP" in outputtext[i+1] :
				html = textile.textile( "<br>")
				html = textile.textile("<h1 style="+"color:Tomato;"+">"+"---------------------------------------- </h1></p>")
				selected_user_file.writelines(html+"\n")
		except IndexError:
			continue	
		if  "interface name" in outputtext[i+1]:
			
			html = textile.textile( "<br>")
			selected_user_file.writelines(html+"\n")
		outputtext[i]=outputtext[i].replace(pattern.group(1),"*"+pattern.group(1)+"* ")
		html = textile.textile( outputtext[i])
		selected_user_file.writelines(html)
		
	except AttributeError:
		
		html = textile.textile( outputtext[i])
		selected_user_file.writelines(html)
	
	#print html
selected_user_file.close()

user_file="outputfile2.txt"
selected_user_file = open(user_file, 'r')
outputtext=selected_user_file.readlines()
selected_user_file.close()
selected_user_file = open("EOSinfo.html", 'w')
html = textile.textile("<h1 style="+"color:Tomato;"+">"+"### End Of Life/Support Information ### </h1></p>")
selected_user_file.writelines(html)
for i in range (len(outputtext)):
	#print outputtext[i]
	pattern=re.search(r"\b(.*:)\s",outputtext[i])
	try:
		try: 
			if "Information Regarding" in outputtext[i+1] :
				html = textile.textile( "<br>")
				html = textile.textile("<h1 style="+"color:Tomato;"+">"+"---------------------------------------- </h1></p>")
				selected_user_file.writelines(html+"\n")
		except IndexError:
			continue	
		outputtext[i]=outputtext[i].replace(pattern.group(1),"*"+pattern.group(1)+"* ")
		html = textile.textile( outputtext[i])
		selected_user_file.writelines(html)
		
	except AttributeError:
		
		html = textile.textile( outputtext[i])
		selected_user_file.writelines(html)
	
	#print html
selected_user_file.close()




#Intergration with SPARK 


filepath    = '/home/debian/workingdir/Topolgyinfo.html'
filetype    = 'text/html'
roomId      = 'Y2lzY29zcGFyazovL3VzL1JPT00vNDk1OWQ4MzAtMThhNy0xMWU4LWI1MDktYjE2ZmRlMGU1M2Qx'
token       = 'YjQ0NGJmMjctMWM5MS00NzI1LTkxZjgtZDFhZGI3MWI5MjY5NTc2NzRmMTYtODFh'
url         = "https://api.ciscospark.com/v1/messages"

my_fields={'roomId': roomId, 
           'text': 'here is the latest Update of the Network',
           'files': ('Network Report', open(filepath, 'rb'), filetype)
           }
m = MultipartEncoder(fields=my_fields)
r = requests.post(url, data=m,
                  headers={'Content-Type': m.content_type,
                           'Authorization': 'Bearer ' + token})
filepath    = '/home/debian/workingdir/EOSinfo.html'
my_fields={'roomId': roomId, 
           'text': 'here is the latest Update of the End Of Life/Support',
           'files': ('End of Support Infromation Report', open(filepath, 'rb'), filetype)
           }
m = MultipartEncoder(fields=my_fields)
r = requests.post(url, data=m,
                  headers={'Content-Type': m.content_type,
                           'Authorization': 'Bearer ' + token})
filepath    = '/home/debian/workingdir/TopolgyGraph.png'
filetype    = 'image/png'
roomId      = 'Y2lzY29zcGFyazovL3VzL1JPT00vNDk1OWQ4MzAtMThhNy0xMWU4LWI1MDktYjE2ZmRlMGU1M2Qx'
token       = 'YjQ0NGJmMjctMWM5MS00NzI1LTkxZjgtZDFhZGI3MWI5MjY5NTc2NzRmMTYtODFh'
url         = "https://api.ciscospark.com/v1/messages"

my_fields={'roomId': roomId, 
           'text': 'here is the Image of the Network',
           'files': ('Network Graph Topolgy Report', open(filepath, 'rb'), filetype)
           }
m = MultipartEncoder(fields=my_fields)
r = requests.post(url, data=m,
                  headers={'Content-Type': m.content_type,
                           'Authorization': 'Bearer ' + token})
                      
#print r.json()		
#delete from routers;
#alter table routers modify Modules VARCHAR(2024)
deinit()
