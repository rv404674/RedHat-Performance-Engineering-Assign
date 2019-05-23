openshift_VM = open("openshift_VM.audit.log")
lines = openshift_VM.readlines()

baremetal_audit = open("baremetal_audit.log")
lines2 = baremetal_audit.readlines()


def find_ip_address():
    # i am only parsing "baremetal log file" for this as ipaddres = '?'
    # everywhere in openshift log file

    ip_list = {}

    for line in lines2:
        lst = line.split()

        for i in lst:
            if i.split('=')[0] == 'addr':
                ipaddres = i.split('=')[1]

                if ipaddres != '?':
                    if ipaddres in ip_list.keys():
                        ip_list[ipaddres] += 1
                    else:
                        ip_list[ipaddres] = 1

    for i, j in ip_list.iteritems():
        print("ipaddres " + str(i) + " log statements " + str(j))

    print("There is only one id address present in both the log files - " + str(ip_list.keys()[0]))


def find_diff_syscall():
    finaldict = {}

    for line in lines:
        lst = line.split()

        if lst[0] == 'type=SYSCALL':
            newlst = lst[3].split('=')

            if newlst[1] in finaldict.keys():
                finaldict[newlst[1]] += 1
            else:
                finaldict[newlst[1]] = 1

    print("Different SysCall with their count")
    print("I have used 'syscall' to uniquely identify syscalls")
    for i, j in finaldict.iteritems():
        print("syscallno " + str(i) + " calls " + str(j))
    print("")


def multiple_syscalls_process():
    process_dict = {}

    for line in lines:
        lst = line.split()

        if lst[0] == 'type=SYSCALL':

            newlst2 = lst[12].split('=')
            if newlst2[1] in process_dict.keys():
                process_dict[newlst2[1]] += 1
            else:
                process_dict[newlst2[1]] = 1

    print("Following are the Process that made multiple sys calls")
    for i, j in process_dict.iteritems():
        if j > 1:
            print("Process " + str(i) + " made " + str(j) + " sys calls")
    # else :
    # 	print(i,j)
    # 	print("Process " + str(i) + "made just one sys call")

    print("")


def failed_syscall():
    auid_list = []

    for line in lines:
        lst = line.split()

        if lst[0] == 'type=SYSCALL':

            # checks for failed sys call
            if lst[4].split('=')[1] == "no":
                if lst[13].split('=')[1] not in auid_list:
                    auid_list.append(lst[13].split('=')[1])

    if len(auid_list) == 0:
        print("no sys call failed")
    else:
        for i in auid_list:
            print(i)

    print('')


# 1. How many different syscalls were made and what is count of each ?
find_diff_syscall()

# 2.List PIDs of the process that are making multiple syscalls
multiple_syscalls_process()

# 3.Get the auid parameter for a syscall that failed(if any).
failed_syscall()

# 4 and 5. How many systems have been mentioned in the logs ? List their hostname and IPs
# Which system has generated the most number of logs ?
find_ip_address()
