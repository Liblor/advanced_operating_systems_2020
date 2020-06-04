[![Build Status](https://travis-ci.com/Liblor/advanced_operating_systems_2020.svg?token=Zrce2EeAvy4vhtiTbyaH&branch=master)](https://travis-ci.com/github/Liblor/advanced_operating_systems_2020)

> :warning: **If you are enrolled in this course do not proceed further**: Coming up with your own design decisions is an integral part of the project and therefore the course. Having a look at our implementation might violate the ETHZ guidelines.

# Advanced Operating Systems - FS20
> This course is intended to give students a thorough understanding of design and implementation issues for modern multicore operating systems.
> 
> We will cover key design issues in implementing an operating system, such as memory management, inter-core synchronization, scheduling, protection, inter-process communication, device drivers, and file systems, paying particular attention to system designs that differ from the traditional monolithic arrangements of Unix/Linux and Windows.
> 
> The course is structured around a significant project which builds up, over the course of the semester, a fairly complete, full-featured multicore operating system for the ARM-based Toradex board. The OS is based on the [Barrelfish](http://www.barrelfish.org/) open-source multikernel developed at ETHZ in collaboration with Microsoft Research. 

[ETHZ - Advanced Operating Systems](https://www.systems.ethz.ch/courses/spring2020/aos)

Our report of the project can be found [here](https://github.com/Liblor/advanced_operating_systems_2020/raw/master/report/report.pdf).

```
Barrelfish CPU driver starting on ARMv8 (BSP)
kernel 0: ARMv8-A: 4 cores in system

................................
......._....___..____.._..._....
....../ \  / _ \/ ___|| |.| |...
...../ _ \| |.| \___ \| |.| |...
..../ ___ \ |.| |...) |  _  |...
.../_/...\_\___/|____/|_|.|_|...
................................
Welcome to AOSH.................
AOSH Operating System Shell.....
................................

aosh >>> nslist server
There are 5 services matching query 'server':
serverinit
serverblockdriver
serverfilesystem
servermonitor0
servermonitor1
serverprocess
serverserial

aosh >>> cat myfile2.txt
File size is 70
I love deadlines. I like the whooshing sound they make as they fly by.

aosh >>> oncore -f arp
Querying ARP cache...
00:14:2d:64:13:a4 - 10.0.0.2
00:25:96:12:34:56 - 10.0.0.1
1C:96:AE:84:4A:E9 - 10.0.0.3

aosh >>> ip
10.0.0.2

aosh >>> pwd
/sdcard/team/

aosh >>> ls members
.
..
bean
chris
eikendev
liblor
```

## Group Members
- Andrin Bertschi - [abertschi](https://github.com/abertschi)
- Raphael Eikenberg - [eikendev](https://github.com/eikendev)
- Christian Leopoldseder - [leopoldsedev](https://github.com/leopoldsedev)
- Loris Reiff - [Liblor](https://github.com/Liblor/applied_sec_lab)
