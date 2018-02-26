# PythonProject_Group8
Cisco Engineering Incubator 5.0 - Python Group 8 
Raslan Rassalan, Victoria Fetisova, Radu Postolache

!!! To Run the program simply Run: python Project.py


!!! For the program to run Successfully you must import and install all modules Used                                                     
!!! You Must have Mysql database as a localhost with Name(Case Senstive): PythonProject,username: root,Password: root                   
!!! MySql database Should contain a table called(Case Senstive): routers                                                                 
!!! the table should contain the following columns as varchar type (Name Case Senstive):Hostname,IP,Password,OS_Ver,                     
!!! HW_Ver,INTDESCSTAT,Modules,ConnectedRouters                                                                                         
!!! IP column should be a unique Index                                                                                                   
!!! The Regex was written based on the output of CISCO 7206VXR Router Running IOS 15.2(4)M7                                             




The program starts by asking the user to input the filename and extension for the files that contain the IP address range,
and for the passwords that should be used when authenticating. If the files exist, the IP adresses will be checked for validity. 

The host IP adresses will be pinged and if they reply they will be considered Online. 
The authentication begins after waiting for the ICMP echo reply from every host.
If any of the passwords from the passwords file are matching, then authentication will be successful. 
If not, the user will be prompted to check the password.

After succesfully authenticating, the script will output the following information:
Management IP address
Password
Hostname
OS version
Hardware version
interface status for every interface 
connected modules

All the information collected from the routers will be stored in a MySQL database containing the following columns :
Hostname, IP, Password, OS_Ver, HW_Ver, INTDESCSTAT, Modules, ConnectedRoutes. 

Cisco Spark integration has as well been created. Using information from https://developer.ciscospark.com/bots.html,
a bot can be added to a Spark space an the bot will write the topology information directly in the Spark room.

The end of life / end of support information is gathered through an API from https://developer.cisco.com/. 

Using the results from the command "show ip route connected", the script will draw a graph diagram describing the topology.
If there is a matching pair of routers that see each other as connected, the program will draw them in a point to point connection. 
If a network is connected to only one of the routers, then it will be assumed that the network  is a LAN.

The program is scalable and will accept any topology containing routers using the same OS version. 

All the final information is finally converted to HTML for convenient integration into web sites, 
resulting in one HTML file for the topology information and another file for the end of life / end of support information.
