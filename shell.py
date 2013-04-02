#!/usr/bin/env python

# this code does not work.

import sys
from pyproxmox import *

def main():
	# connect to proxmox
	px_auth = prox_auth('10.13.37.202','apiuser@pve','apipasswd')
	global px 
	px = pyproxmox(px_auth)
	# print px.getClusterStatus()

	args = sys.argv[:]

	# if no arguements print usage
	if len(args) == 1:
		usage()
		sys.exit(0)

	method = args[1]

	# Get methods
	if method == 'cluster':
		cluster(args)
	if method == 'node':
		node(args)


def cluster(args):
	action = args[2]
	if action == 'status':
		print px.getClusterStatus()
	if action == 'backup':
		print px.getClusterBackupSchedule()
	if action == 'nextid':
		print px.getClusterVmNextId()


def node(args):
	method = args[2]
	if method == 'network':
		print px.getNodeNetworks('proxmox')



def usage():
	print "Usage: %s <action> " % (sys.argv[0])




if __name__ == '__main__':
  main()
  sys.exit(0)
