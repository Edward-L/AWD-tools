#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import shutil
import hashlib
import time
import argparse

def read_chunks(fp, num):
	fp.seek(0)
	chunk = fp.read(num)
	while chunk:
		yield chunk
		chunk = fp.read(num)
	else:
		fp.seek(0)

def md5sum(filename):
	m = hashlib.md5()
	if isinstance(filename, basestring) \
	and os.path.exists(filename):
		with open(filename, 'rb') as f:
			for chunk in read_chunks(f, 2048):
				m.update(chunk)
	else:
		return "nothing"
	return m.hexdigest()

def create_md5list(path):
	with open('md5list.txt', 'w') as fp:
		for dirpath, dirname, filenames in os.walk(path):
			for filename in filenames:
				filepath = os.path.join(dirpath, filename)
				content = filepath + ':' + md5sum(filepath)
				fp.write(content)
				fp.write('\n')	

def check_file(check_path,backup_path):
	with open('md5list.txt') as fp:
		md5list = fp.read()
	now_files = []
	for dirpath, dirname, filenames in os.walk(check_path):
		for filename in filenames:
			filepath = os.path.join(dirpath, filename)
			if filepath not in md5list:
				os.remove(filepath)
				print '[-] Notice! delete file: %s' % filepath
			elif md5sum(filepath) not in md5list:
				restore(filepath,check_path,backup_path)
				print '[-] Notice! restore file: %s' % filepath
			else:
				now_files.append(filename)

	for dirpath, dirname, filenames in os.walk(backup_path):
		for filename in filenames:
			if filename not in now_files:
				filepath = os.path.join(dirpath, filename)
				backdelfile(filename,dirpath,check_path,backup_path)

def backdelfile(filename,dirpath,check_path,backup_path):
	backup_to_path = dirpath.replace(backup_path,check_path)
	if not os.path.exists(backup_to_path):
		os.makedirs(backup_to_path)
	pathfile = os.path.join(dirpath, filename)
	backup_to_path_file = os.path.join(backup_to_path,filename)
	shutil.copy(pathfile, backup_to_path_file)
	print '[-] Notice! back del file: %s' % pathfile

def restore(pathfile,check_path,backup_path):
	if os.path.exists(pathfile):
		os.remove(pathfile)
	backup_path_file = pathfile.replace(check_path, backup_path)
	shutil.copy(backup_path_file, pathfile)
	print '[-] Notice! restore file: %s' % pathfile

def work(check_path,backup_path):
	if os.path.exists(backup_path):
		shutil.rmtree(backup_path)
	shutil.copytree(check_path, backup_path)
	print '[+] backup complete...'
	create_md5list(check_path)
	print '[+] create md5list complete...'
	while True:
		check_file(check_path,backup_path)
		time.sleep(1)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(
		usage="%(prog)s -w [path] -b [path]",
		description=('''
		Introduce：Simple File Monitor!  by Edward_L''')
	)
	parser.add_argument('-w', '--watch', action="store", dest="check_path",
						default="/var/www/html/", help="directory to watch,default is /var/www/html/")
	parser.add_argument('-b', '--backup', action="store", dest="backup_path",
						default="/tmp/backup/", help="directory to backup,default is /tmp/backup/")
	args = parser.parse_args()
	print args.check_path, args.backup_path
	exit()
	work(check_path,backup_path)
