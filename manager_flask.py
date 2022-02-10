#test SFTP
#MODULE_PATH = "/usr/local/lib/python3.6/dist-packages/flask/__init__.py"
#MODULE_NAME = "flask"
#import importlib.util
import sys
#spec = importlib.util.spec_from_file_location(MODULE_NAME, MODULE_PATH)
#module = importlib.util.module_from_spec(spec)
#sys.modules[spec.name] = module
#spec.loader.exec_module(module)
import argparse
import logging
from typing import List
import threading
import requests
#sys.path.append("/usr/local/lib/python3.6/dist-packages/flask/__init__.py")
#from flask import Flask
#from flask import requests
#sys.path.append("/usr/local/lib/python3.6/dist-packages/flask/")
from _thread import (
	start_new_thread,
)
import time
import paramiko
import socket
from paramiko.py3compat import u
from flask import Flask
from flask import request

from pybatfish.client.commands import *
from pybatfish.question.question import load_questions
from pybatfish.question import bfq
from pybatfish.datamodel.flow import HeaderConstraints, PathConstraints

import os.path
from os import path

import json
import sys
from pybatfish.question import bfq
from pybatfish.datamodel import HeaderConstraints, PathConstraints, Hop
from pybatfish.question.question import load_questions
from pybatfish.client.commands import bf_init_snapshot, bf_set_network, bf_upload_diagnostics
from typing import List
import json
from command import *
from policy import *
from experiment import *
from utils import *
import json
import sys
from specification import *
import jsonpickle
from scapy.all import *


ip = ""
tech_id = 1
ticket = 1
ssh_dir = "/Users/henah/Heimdall/id_rsa"

app = Flask(__name__)

mutex_lock = threading.Lock()

ticket_dict={}

shadow_dict={
	"1": {
		"server": "ms0806.utah.cloudlab.us", 
		"username": "henahkoo", 
		"port": 22 
	},
 	"2": {
		"server": "amd243.utah.cloudlab.us", 
		"username": "henahkoo", 
		"port": 22 
	},
}

command_dict={
	"1":["ip","help"],
	"2":["help"]
}

class Client(object):
	def setup_batfish(self):
		bf_session.host = "localhost"
		#bf_set_network('example_dc')

	def load_snapshot(self, snapshot_dir: str, name: str):
		bf_init_snapshot(snapshot_dir, name, overwrite=True)

	def check_traffic(self, snapshot: str, reference_snapshot: str):
		# bf_set_snapshot(name)
		load_questions()
		header = HeaderConstraints(srcIps="0.0.0.0/0", dstIps="0.0.0.0/0", ipProtocols=["tcp"])
		path = PathConstraints(startLocation="/as1/", endLocation="/as1/")
		# result = bfq.differentialReachability(headers=header) \
		#     .answer(snapshot=snapshot, reference_snapshot=reference_snapshot).frame()
		result = bfq.reachability(headers=header, pathConstraints=path) \
			.answer(snapshot=reference_snapshot).frame()
		result.to_csv("out_sgx.csv")
		print("Completed*****")
		#  return result.count > 0
		#  print(result.to_string())
		# for idx, row in result.iterrows():
		#   view_diff_frame(row)

def perform_sftp_get(ticket):
	k = paramiko.RSAKey.from_private_key_file(ssh_dir)
	client = paramiko.SSHClient()
	client.load_system_host_keys()

	t = paramiko.Transport("beluga21", 22)
	t.connect(username="aayushag",pkey=k)

	sftp = paramiko.SFTPClient.from_transport(t)
	
	#logging.info("Copying file from shadow server to manager")
	if ticket == 1:
		sftp_file = "a.txt"
	if ticket == 2:
		sftp_file = "b.txt"

	file_src = "/users/aayushag/{}".format(sftp_file)
	#file_dst = "/home/aayush/Desktop/Fall20-Mininet/{}".format(sftp_file)
	file_dst = "/users/aayushag/Fall20-Mininet/flask_implementations/{}".format(sftp_file)

	sftp.get(file_src,file_dst)
	sftp.close()
	t.close()

def perform_sftp_put(ticket):
	k = paramiko.RSAKey.from_private_key_file(ssh_dir)
	client = paramiko.SSHClient()
	client.load_system_host_keys()

	t = paramiko.Transport("ms0917.utah.cloudlab.us", 22)
	t.connect(username="aayushag",pkey=k)

	sftp = paramiko.SFTPClient.from_transport(t)

	#logging.info("Copying file from manager to production network")
	if ticket == 1:
		sftp_file = "a.txt"
	if ticket == 2:
		sftp_file = "b.txt"

	file_src = "/users/aayushag/test_graphene/graphene/Examples/python-simple/scripts/{}".format(sftp_file)
	file_dst = "/users/aayushag/{}".format(sftp_file)

	sftp.put(file_src,file_dst)
	sftp.close()

	t.close()

@app.route("/delete_shadow")
def delete_shadow():
	global ticket_dict
	tech_id = request.headers["Tech-id"]
	ticket = request.headers["Ticket"]
	
	# Remove tech's details that are associated with the ticket
	# print("Before deleting {}".format(ticket_dict))
	# if ticket not in ticket_dict:
	# 	ticket_dict[ticket]=[]
	# 	ticket_dict[ticket].append(tech_id)
	# else:
	# 	ticket_dict[ticket].remove(tech_id)
	# print("After deleting {}".format(ticket_dict))

	# Retrieve files from shadow server to manager
	#perform_sftp_get(int(ticket))

	# Send files to production network
#	perform_sftp_put(int(ticket))

	# Delete the shadow server
	#logging.info("Deleting shadow server: {}".format(ticket))
	#logging.info("Informing Controller tech_id={} ticket={}".format(tech_id,ticket))

	#ret_msg = shadow_dict[ticket]["username"] + shadow_dict[ticket]["server"]
	return "SUCCESS"

@app.route("/push_changes")
def push_changes():
	global ticket_dict
	tech_id = request.headers["Tech-id"]
	ticket = request.headers["Ticket"]

	# Retrieve files from shadow network
	perform_sftp_get(int(ticket))
	
	# Send files to production network
#	perform_sftp_put(int(ticket))

def batflish_client():
	logging.info("Verifying config with batfish server")
	client = Client()

	client.setup_batfish()
	load_questions()
	# ospf
	# data = {
	# 	"base": "/users/aayushag/test_graphene/graphene/Examples/python-simple/scripts/ospf",
  	# 	"affected_nodes": ["/pc[1-3,8-9]/"],
  	# 	"sensitive_nodes": [],
	# 	"allowed_command": ["NodeCommand(\"esw.*\", \"\", {\"up\"})"],
	# 	"invariants": "Reachability(\"esw1\", \"11.1.1.0\")"
	# }

	# reconfigure
	# data = {
  	# 	"base": "/users/aayushag/test_graphene/graphene/Examples/python-simple/scripts/vlan",
	# 	"affected_nodes": ["/pc[1-3,8-9]/"],
	# 	"sensitive_nodes": [],
	# 	"allowed_command": ["NodeCommand(\"esw.*\", \"\", {\"up\"})"],
	# 	"invariants": "Reachability(\"esw1\", \"11.1.1.0\")"
	# }

	# vlan
	# data = {
	# 	"base": "/users/aayushag/test_graphene/graphene/Examples/python-simple/scripts/vlan",
	# 	"affected_nodes": ["/pc[2,8]/"],
	# 	"sensitive_nodes": [],
	# 	"allowed_command": ["NodeCommand(\"esw.*\", \"\", {\"up\"})"],
	# 	"invariants": "Reachability(\"esw1\", \"11.1.1.0\")"
	# }
	data = {
        "base": "/Users/henah/Heimdall/UniversityExample/as3border2-interface-misconfig",
        "affected_nodes": ['host6','host7'],
        "sensitive_nodes": [],
        "allowed_command": ["NodeCommand(\"/.*host.*/\", \"\", {\"ip\"})",
                            "NodeCommand(\"/.*border.*/\", \"\", {\"login\"})"],
        "invariants": "Policy([ApplicationAction(\"SSH\")], [SrcNodeResource(\"host1\"), DstNodeResource(\"host2\")])"
    }

	# as2border1
	# data = {
  	# 	"base": "/users/aayushag/test_graphene/graphene/Examples/python-simple/scripts/as2border1-routing",
	# 	"affected_nodes": ["/host1[3-5]/"],
	# 	"sensitive_nodes": [],
	# 	"allowed_command": ["NodeCommand(\".*core.*\", \"\", {\"down\"})"],
	# 	"invariants": "Reachability(\"as1border1\", \"2.128.1.0/24\")"
	# }

	# as2core1
	# data = {
	# 	"base": "/users/aayushag/test_graphene/graphene/Examples/python-simple/scripts/as2core1-bgp",
	# 	"affected_nodes": ["/host[7-9]/"],
	# 	"sensitive_nodes": [],
	# 	"allowed_command": ["NodeCommand(\".*core.*\", \"\", {\"down\"})"],
	# 	"invariants": "Reachability(\"as1border1\", \"2.128.1.0/24\")"
	# }

	# as3border2
	# data = {
	# 	"base": "/users/aayushag/test_graphene/graphene/Examples/python-simple/scripts/as3border2-interface-misconfig",
	# 	"affected_nodes": ["/host17/"],
	# 	"sensitive_nodes": [],
	# 	"allowed_command": ["NodeCommand(\".*core.*\", \"\", {\"down\"})"],
	# 	"invariants": "Reachability(\"as1border1\", \"2.128.1.0/24\")"
	# }
	# Reachability("test","test2")
	specification = build_specification_from_dict(data)
	#print(jsonpickle.encode(specification, indent=2))
	#client.load_snapshot("/users/aayushag/graphene/Examples/python-simple/scripts/batfish-example/origin", "origin")
	#client.load_snapshot("/users/aayushag/graphene/Examples/python-simple/scripts/batfish-example/update1", "update1")
	#client.check_traffic("/users/aayushag/graphene/Examples/python-simple/scripts/batfish-example/origin", "update1")

	# client.load_snapshot("origin.zip", "origin")
	#client.load_snapshot("update1", "update1")
	#client.check_traffic("origin", "update1")
	# client.check_traffic("origin", "origin")
	#client.check_traffic("update1","update1")
	# logging.info("Verification completed")
	# if (os.path.exists("/users/aayushag/test_graphene/graphene/Examples/python-simple/out_sgx.csv")):
	# 	return True
	# else:
	# 	return False

@app.route("/check_spec")
def check_spec():
	tech_id = request.headers["Tech-id"]
	ticket = request.headers["Ticket"]
	# call check_specification
	# data = {
	# 	"base": "/users/aayushag/test_graphene/graphene/Examples/python-simple/scripts/ospf",
  	# 	"affected_nodes": ["/pc[1-3,8-9]/"],
  	# 	"sensitive_nodes": [],
	# 	"allowed_command": ["NodeCommand(\"esw.*\", \"\", {\"up\"})"],
	# 	"invariants": "Reachability(\"esw1\", \"11.1.1.0\")"
	# }
	
	# specification = build_specification_from_dict(data)
	# print(jsonpickle.encode(specification, indent=2))
	batflish_client()
	return "SUCCESS"



@app.route("/push_all_config")
def push_all_config():
	start = time.perf_counter()
	tech_id = request.headers["Tech-id"]
	ticket = request.headers["Ticket"]
	#logging.info("Contacted by Technician for push_all_config for tech_id={} and ticket={}".format(tech_id,ticket))   
	#logging.info("Requesting Controller to push all config")
	get_request = "http://{}:{}/push_all_config".format("10.81.1.21", 2345)
	headers={
		"Tech-Id": str(tech_id),
		"Ticket": str(ticket),
	}
	ret_msg = requests.get(get_request,headers=headers,verify=False,timeout=10)
	#logging.info("Controller returned {}".format(ret_msg.text))

	#logging.info("Verifying config (with batfish)")
	success = check_invalid_policies("/users/aayushag/test_graphene/graphene/Examples/python-simple/scripts/policies-enterprise.csv", "/users/aayushag/test_graphene/graphene/Examples/python-simple/scripts/Working_Enterprise")
	ret_msg = ""
	#logging.info("Value= {}".format(success))
	success = True
	if success == True:
		ret_msg = "ALLOW"
		k = paramiko.RSAKey.from_private_key_file(ssh_dir)
		client = paramiko.SSHClient()
		client.load_system_host_keys()

		t = paramiko.Transport("beluga22", 22)
		t.connect(username="aayushag",pkey=k)

		sftp = paramiko.SFTPClient.from_transport(t)

		#logging.info("Sending config from Manager to Production")
		# if node_id == 1:
		# 	sftp_file = "origin.zip"
		# if node_id == 2:
		# 	sftp_file = "origin.zip"
		dir_orig = "/users/aayushag/test_graphene/graphene/Examples/python-simple/origin/configs"
		files = os.listdir(dir_orig)
		files_to_send=[]
		for f in files:
			files_to_send.append(dir_orig+"/"+f)
		#logging.info("files to send are{}".format(files_to_send))
		ret_msg = ''
		
		# perform sftp put
		for f,f1 in zip(files_to_send,files):
			file_src = f
			file_dst = "/users/aayushag/config_dir/"+f1
			#logging.info("Sending files to production network src={}\ndst={}\n\n".format(file_src,file_dst))

			#sftp.chmod(file_src,0o777)
			#try:
			sftp.put(file_src,file_dst)
			ret_msg = "SUCCESS"
			#except Exception as e:
			ret_msg = "FAILED"
		
		sftp.close()
		t.close()

		a_ip = "128.110.217.68"
		a_port = 3456
		#logging.info("Contacting Network Admin about Node-Id={} and command={}".format(node_id,command))
		# form request to send manager running at m_ip and m_port
		get_request = "http://{}:{}/push_all_config".format(a_ip, a_port)
		# headers={
		# 	"Node-Id": str(node_id),
		# }
		#logging.info("Contacting Network Admin")
		responses = requests.get(get_request,timeout=10)
		#logging.info("Admin replied {}".format(responses.text))
		if "SUCCESS" in responses.text:
			ret_msg = "SUCCESS"
		else:
			ret_msg = "FAILED"
	else:
		#logging.info("Verifier DISALLOWED")
		ret_msg = "DISALLOwwWeeeeeeedd"
	

	#logging.info("Sending Controller the reply from Admin")
	get_request = "http://{}:{}/msg_from_manager".format("10.81.1.21", 2345)

	ret_msg1 = requests.get(get_request,verify=False,timeout=10)
	#logging.info("Controller returned {}".format(ret_msg1.text))

	return ret_msg1.text



@app.route("/push_config")
def push_config():
	
	#logging.info("Contacted by controller for push_config Node-Id:{} ")

	global ticket_dict
	p_ip = "10.81.1.22"
	p_port = 4567
	node_id = int(request.headers["Node-Id"])

	########### exp3 case2 #############
	# success = batflish_client()
	# if success == True:
	# 	#logging.info("Verifier ALLOWED")
	# else:
	# 	logging.info("Verifier DISALLOWED")

	########################

	success = check_invalid_policies("/users/aayushag/test_graphene/graphene/Examples/python-simple/scripts/policies-test.csv", "/users/aayushag/test_graphene/graphene/Examples/python-simple/scripts/origin")

	########### exp3 case1 #############

	success = False
	########################


	# Send files to Production network
	if success == True:
		k = paramiko.RSAKey.from_private_key_file(ssh_dir)
		client = paramiko.SSHClient()
		client.load_system_host_keys()

		t = paramiko.Transport("beluga22", 22)
		t.connect(username="aayushag",pkey=k)

		sftp = paramiko.SFTPClient.from_transport(t)

		#logging.info("Sending config from Manager to Production")
		if node_id == 1:
			sftp_file = "origin.zip"
		if node_id == 2:
			sftp_file = "origin.zip"

		file_src = "/users/aayushag/test_graphene/graphene/Examples/python-simple/{}".format(sftp_file)
		sftp.chmod(file_src,0o777)
		file_dst = "/users/aayushag/Fall20-Mininet/{}".format(sftp_file)
		ret_msg = ''
		
		#logging.info("Sending files to production network")
		try:
			sftp.put(file_src,file_dst)
			ret_msg = "SUCCESS"
		except Exception as e:
			ret_msg = "FAILED"
			
		# sftp.put(file_src,file_dst)
		# ret_msg = "SUCCESS"
			
		sftp.close()

		t.close()
		
		a_ip = "10.81.1.22"
		a_port = 3456
		##logging.info("Contacting Network Admin about Node-Id={} and command={}".format(node_id,command))
		# form request to send manager running at m_ip and m_port
		get_request = "http://{}:{}/push_config".format(a_ip, a_port)
		headers={
			"Node-Id": str(node_id),
		}
		#logging.info("Contacting Network Admin about Node-Id={}".format(node_id))
		responses = requests.get(get_request,headers=headers,timeout=10)
		#logging.info("Admin replied {}".format(responses.text))
		if "1" in responses.text:
			ret_msg = "SUCCESS"
		else:
			ret_msg = "FAILED"
		return ret_msg
	else:
		#logging.info("Verifier DISALLOWED")
		#logging.info("Not sending config to production network")
		ret_msg = "FAILED"
		return ret_msg

		

@app.route("/create_shadow")
def create_shadow():
	global ticket_dict
	tech_id = request.headers["Tech-id"]
	ticket = request.headers["Ticket"]
	print("Function called")
	if ticket not in ticket_dict:
		ticket_dict[ticket]=[]
		ticket_dict[ticket].append(tech_id)
	#print("Before deleting {}".format(ticket_dict))
	# Contact controller to start the gns3server
	# c_ip = "10.81.1.21"
	# c_port = 2345
	c_ip = "172.26.8.208"
	c_port = 2345
	get_request = "http://{}:{}/create_shadow".format(c_ip, c_port)
	headers={
		"Tech-id": str(tech_id),
		"Ticket": str(ticket),
	}
	#logging.info("Contacting Controller for creating shadow with Tech-Id={} Ticket={}".format(tech_id,ticket))
	responses = requests.get(get_request,headers=headers,timeout=10)
	#logging.info("Controller replied {}".format(responses.text))
	
	#ret_msg = shadow_dict[ticket]["username"] + shadow_dict[ticket]["server"]
	# return "DONE"
	return responses.text

@app.route("/check_command")
def check_command():
	node_id = request.headers["Node-Id"]
	command = request.headers["Command"]
	contact_admin = int(request.headers["Admin"])
	#logging.info(contact_admin)

	#logging.info("Contacted by controller for Node-Id:{} and command={}".format(node_id,command))
	a_ip = "10.81.1.22"
	a_port = 3456
	if contact_admin == 1:
		##logging.info("Contacting Network Admin about Node-Id={} and command={}".format(node_id,command))
		# form request to send manager running at m_ip and m_port
		get_request = "http://{}:{}/check_command".format(a_ip, a_port)
		headers={
			"Node-Id": str(node_id),
			"Command": str(command),
			"Admin" : str(contact_admin)
		}
		#logging.info("Contacting Network Admin about Node-Id={} and command={}".format(node_id,command))
		responses = requests.get(get_request,headers=headers,timeout=10)
		#logging.info("Admin replied {}".format(responses.text))
		if "1" in responses.text:
			ret_msg = "Node-Id={} and command={} is ALLOWED1".format(node_id,command)
		else:
			ret_msg = "Node-Id={} and command={} is DISALLOWED0".format(node_id,command)
	else:
		print(contact_admin)
		ret_msg = "Error***********"

	# ret_msg = ""
	# flag = 0
	# for key in command_dict:
	# 	if key == node_id:
	# 		if command in command_dict[key]:
	# 			#logging.info("Node-Id={} and command={} is ALLOWED1".format(command,node_id))
	# 			ret_msg = "Node-Id={} and command={} is ALLOWED1"
	# 			flag = 1
	# 			break
	# 	else:
	# 		flag = 0 
	# 		ret_msg = "Node-Id={} and command={} is DISALLOWED0"
	
	# return ret_msg

	return ret_msg

@app.route("/check_trace")
def check_trace():
	src_ip = request.headers["Src_IP"]
	dst_ip = request.headers["Dst_IP"]
	src_port = int(request.headers["Src_Port"])
	dst_port = int(request.headers["Dst_Port"])
	proto = int(request.headers["Proto"])

	logging.info(
		"Received check_trace comamnd from technician for \
		src_ip={},dst_ip={}, src_port={}, dst_port={} and protocol={}"\
		.format(src_ip,dst_ip,src_port,dst_port,proto)
	)

	logging.info("Sending check trace command to Production Network")
	prod_ip = "10.81.1.22"
	prod_port = 3456

	get_request = "http://{}:{}/check_trace".format(prod_ip, prod_port)
	headers={
		"Src_IP": str(src_ip),
		"Dst_IP": str(dst_ip),
		"Src_Port": str(src_port),
		"Dst_Port": str(dst_port),
		"Proto": str(proto),
	}
	ret_msg = requests.get(get_request,headers=headers,verify=False)

	# If packet capture is successful
	if ret_msg.text == "SUCCESS":
		k = paramiko.RSAKey.from_private_key_file(ssh_dir)
		client = paramiko.SSHClient()
		client.load_system_host_keys()

		t = paramiko.Transport("beluga22", 22)
		t.connect(username="aayushag",pkey=k)

		sftp = paramiko.SFTPClient.from_transport(t)
		
		file_src = "/users/aayushag/Fall20-Mininet/gns3-controller/my.pcap"
		file_dst = "/users/aayushag/Fall20-Mininet/my.pcap"

		# Get the pcap file
		sftp.get(file_src,file_dst)
	
	return ret_msg.text


@app.route("/check_trace_2")
def check_trace_2():
	src_ip = request.headers["Src_IP"]
	dst_ip = request.headers["Dst_IP"]
	src_port = int(request.headers["Src_Port"])
	dst_port = int(request.headers["Dst_Port"])
	proto = int(request.headers["Proto"])

	logging.info(
		"Received check_trace_2 comamnd from technician for \
		src_ip={},dst_ip={}, src_port={}, dst_port={} and protocol={}"\
		.format(src_ip,dst_ip,src_port,dst_port,proto)
	)

	logging.info("Sending check trace 2 command to Production Network")
	prod_ip = "10.81.1.22"
	prod_port = 3456

	get_request = "http://{}:{}/check_trace_2".format(prod_ip, prod_port)
	ret_msg = requests.get(get_request,verify=False)

	# If packet capture is successful
	if ret_msg.text == "SUCCESS":
		k = paramiko.RSAKey.from_private_key_file(ssh_dir)
		client = paramiko.SSHClient()
		client.load_system_host_keys()

		t = paramiko.Transport("beluga22", 22)
		t.connect(username="aayushag",pkey=k)

		sftp = paramiko.SFTPClient.from_transport(t)
		
		file_src = "/users/aayushag/Fall20-Mininet/gns3-controller/my.pcap"
		file_dst = "/users/aayushag/Fall20-Mininet/my.pcap"

		# Get the pcap file
		sftp.get(file_src,file_dst)

		# Filter the captured trace
		try:

			scapy_cap = rdpcap(file_dst)
		except:
			print("error")
		count =1
		try:
			writer=PcapWriter("my2.pcap",append=True)
		except:
			pass

		for packet in scapy_cap:
			if packet.haslayer(IP):
				p_IP = packet.getlayer(IP)
				if (str(p_IP.proto) == str(proto)):
					# TCP protocol
					if (p_IP.proto == 6):
						p_TCP =packet.getlayer(TCP)
						if  p_IP.src == src_ip and p_IP.dst == dst_ip \
							and p_TCP.sport and p_TCP.dport:
						#if 1:
							print ("TCP Packet to be saved")
							writer.write(packet)
						else:
							print("Packet to be discarded... Invalid TCP packet")
					# UDP protocol
					elif (p_IP.proto == 17):
						p_UDP =packet.getlayer(UDP)
						if  p_IP.src == src_ip and p_IP.dst == dst_ip \
							and p_UDP.sport and p_UDP.dport:
							print ("UDP Packet to be saved")
							writer.write_packet(packet)
						else:
							print("Packet to be discarded... Invalid UDP packet")
					else:
						print("Invalid protocol")
				else:
					print ("Packet to be discarded... Invalid Protocol")
			else:
				print("Packet to be discarded... No IP layer")
		#writer.close()
		
	return ret_msg.text

# Send blacklist to Controller
def send_blacklist():
	k = paramiko.RSAKey.from_private_key_file(ssh_dir)
	client = paramiko.SSHClient()
	client.load_system_host_keys()

	t = paramiko.Transport("beluga21", 22)
	t.connect(username="aayushag",pkey=k)

	sftp = paramiko.SFTPClient.from_transport(t)

	#logging.info("Sending config from Manager to Production")
	# if node_id == 1:
	# 	sftp_file = "origin.zip"
	# if node_id == 2:
	# 	sftp_file = "origin.zip"
	dir_orig = "/users/aayushag/test_graphene/graphene/Examples/python-simple/origin/configs"
	files = os.listdir(dir_orig)
	files_to_send=[]
	for f in files:
		files_to_send.append(dir_orig+"/"+f)
	#logging.info("files to send are{}".format(files_to_send))
	ret_msg = ''
	
	# perform sftp put
	for f,f1 in zip(files_to_send,files):
		file_src = f
		file_dst = "/users/aayushag/config_dir/"+f1
		#logging.info("Sending files to production network src={}\ndst={}\n\n".format(file_src,file_dst))

		#sftp.chmod(file_src,0o777)
		#try:
		sftp.put(file_src,file_dst)
		ret_msg = "SUCCESS"
		#except Exception as e:
		ret_msg = "FAILED"
	
	sftp.close()
	t.close()

def main():
	app.run(debug=False, host="128.110.217.31", port=1234)
	
if __name__ == "__main__":
	logging.basicConfig(
		level=logging.INFO,
		format="%(asctime)s %(levelname)s %(message)s",
	)
	main()