# !/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Thu Sep 27 18:29:45 2018
@author: babraham
"""
import re
import time
import pandas as pd


# Parses a honeypot log and converts into a dataframe. Extracts:
# srcIP, srcPt, destIP, destPt, session_id, and timestamp.
# Ex. res = parse_honeypot_log(path-to-honeypot-log.log)

def parse_honeypot_log(honeypot_file):
    with open(honeypot_file, 'r') as f:
        ftext = f.read()
        conn_pat = '[0-9]{4}-[0-9]{2}-[0-9]{2}.* New connection: .* \\[session: .*\\]'
        conn_tup = '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.[0-9]+'
        conns = re.findall(conn_pat, ftext)
        recs = []
        date = ""
        for i, conn in enumerate(conns):
            rec = {}
            dt_str = re.findall('([0-9]{4}-[0-9]{2}-[0-9]{2}.*?)\+', conn)[0]
            if i == 0: date = dt_str.split('T')[0]
            time_obj = time.strptime(dt_str, '%Y-%m-%dT%H:%M:%S.%f')
            rec['ts_hp'] = time.mktime(time_obj)
            src_info = re.findall('New connection: ({})'.format(conn_tup), conn)[0]
            rec['src_ip'], rec['src_pt'] = src_info.split(':')
            dest_info = re.findall('\(({})\)'.format(conn_tup), conn)[0]
            rec['dest_ip'], rec['dest_pt'] = dest_info.split(':')
            rec['session_id'] = re.findall('session: (.*?)\]', conn)[0]
            recs.append(rec)
    newdata = pd.DataFrame(recs)
    return newdata


res = parse_honeypot_log('honeypot2.log')
res.to_csv('honeypot.csv',sep=',')


res1=[]
res2=[]
res3=[]
with open('honeypot2.log') as f:
    for line in f:
        if line.startswith('2018'):
            temp=line.split(' ', 2)
            res1.append(temp[0])
            res2.append(temp[1])
            res3.append(temp[2])


df=pd.DataFrame({'time':res1,'protocol':res2,'details':res3})
df.to_csv('honeypot2_1.csv',sep=',')



#failed connection =18510
failed_connection=0
for i in res3:
    if 'login' in i and 'failed' in i:
        failed_connection+=1
failed_connection


#succeed connection=13440
succeed_connection=0
for i in res3:
    if 'login' in i and 'succeeded' in i:
        succeed_connection+=1
succeed_connection

#connection time=30661
connection_time=[]
for i in res3:
    if 'Connection' in i and 'lost' in i and 'after' in i:
        connection_time.append(int(i.split(' ')[3]))
connection_time


import numpy as np
import matplotlib.pyplot as plt
plt.close()
connection_time=np.asarray(connection_time)
plt.hist(connection_time, bins=np.arange(connection_time.min(), 100)-0.5)
plt.xlabel('Time in Seconds', fontsize=18)
plt.ylabel('Frequency', fontsize=16)
plt.show()



#pass/ IP/





#commends



#check whether there's a bot


#most often found commends


#how many IPs have commends


#login password
connection_password=[]
for i in res3:
    if 'login attempt' in i and ']' in i:
        temp=i.split('[')[1].split(']')[0]
        connection_password.append(temp)

connection_password

username,password=[],[]
for i in connection_password:
    temp=i.split('/')
    username.append(temp[0])
    if len(temp)==2:
        password.append(temp[1])
    else:
        password.append('')

username
password

dic_username,dic_password={},{}

for i in username:
    if i not in dic_username.keys():
        dic_username[i]=0
    else:
        dic_username[i]+=1

for j in password:
    if j not in dic_password.keys():
        dic_password[j]=0
    else:
        dic_password[j]+=1

from collections import Counter
dict(Counter(dic_password).most_common(10))

dict(Counter(dic_username).most_common(10))


#SSH???
#Are these connection all SSH??
#example: Remote SSH version: 'SSH-2.0 PUTTY'
#SHoneyPotSSH
#SSHServie
#

SSH={}
for i in res3:
    if 'Remote SSH version' in i:
        if i not in SSH.keys():
            SSH[i]=0
        else:
            SSH[i]+=1

from collections import Counter
dict(Counter(SSH).most_common(10))


