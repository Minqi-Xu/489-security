Part 3 for Assignment 3


To handle ./portal.sh attack <uid>:
Firstly, we will load the message, which is a list of requests of uid in string format. Then we need to transform it into accessible format. Since the only way of prevent MITM attack of the assignment that I can think of is to set the time window as small as possible. So we want to return the attack list as soon as possible, so that hoping we can send the exact same request to the server before the "valid time" expires.
In order to return as soon as possible, I decided to traverse the request list in the inverse order, and return the required info of the first request of "login" and status with 200 (valid login) as an entire list, because we don't want to waste time on traversing the entire list.



The rest part is the copy of my source code (just in case needed):
# Python 3 server example
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import time
import os
import subprocess

hostName = "0.0.0.0"
serverPort = 8000
usrs = []
attack_lst = []
valid_usr_name = ["test1", "test2", "test3", "test4", "test5"]
time_window = 3 # changable, controls the validity period of the signature, unit: second, has to be int

class Server(BaseHTTPRequestHandler):
  def do_POST(self):
    # get path components, for register and login path_arr[0] = "", path_arr[1] = "register" or "login", and path_arr[2] = <uid>
    #                      for attack, path_arr[0] = "", path_arr[1] = "attack"
    # print("self.path = ", self.path)
    path_arr = self.path.split("/")
    # print("header")
    # print(self.headers)
   
    if len(path_arr) > 3:
      self.send_response(400)
      self.end_headers()
      err_str = "Bad request 400: invalid path"
      self.wfile.write(err_str.encode("ascii"))
      print(err_str)
      return
    
    action = path_arr[1]
    print("action: ", action)
    
    if action == "attack":
      print("attack")
      attack_lst = []
      # load message
      length = self.headers.get('content-length')
      data = self.rfile.read(int(length))
      decode_msg = data.decode('ascii')
      # decode_msg is the list of request in the string format
      # print(decode_msg)

      request_lst = json.loads(decode_msg)
      
      # back traverse the list to find the most recent login with status 200
      for i in range(len(request_lst)-1, -1, -1):
        # print(request_lst[i])
        # print(type(request_lst[i]))
        if request_lst[i]["args"][0] == "login" and request_lst[i]["status"] == 200:
          attack_lst.append({"user":request_lst[i]["args"][1], "data":request_lst[i]["data"]})
          break
      
      self.send_response(200)
      self.send_header('Content-type', 'application/json')
      self.end_headers()
      self.wfile.write(json.dumps(attack_lst).encode('ascii'))
      print("attack list returned")
      
    elif action == "register":
      uid = path_arr[2]
      print("uid: ", uid)
      print("register")
      
      # check whether the uid is valid, if already exits or format not match, then deny
      if uid not in valid_usr_name:
        self.send_response(403)
        self.end_headers()
        err_str = "Forbidden 403: invalid uid format"
        self.wfile.write(err_str.encode("ascii"))
        print(err_str)
        return
      if uid in usrs:
        self.send_response(403)
        self.end_headers()
        err_str = "Forbidden 403: uid already registered"
        self.wfile.write(err_str.encode("ascii"))
        print(err_str)
        return
      
      # load message
      length = self.headers.get('content-length')
      data = self.rfile.read(int(length))
      decode_msg = data.decode('ascii')
      decode_msg_arr = decode_msg.split(" ")
      # decode_msg_arr[0] = ssh-ed25519, decode_msg_arr[1] = public-key, decode_msg_arry[2] = <questid>@s3
      # print("decode_msg")
      # print(decode_msg)
      
      # check key type
      if decode_msg_arr[0] != "ssh-ed25519":
        self.send_response(400)
        self.end_headers()
        err_str = "Bad request 400: invalid ssh-key type"
        self.wfile.write(err_str.encode("ascii"))
        print(err_str)
        return
      
      # add the new user info into the allowed_signers
      usrs.append(uid)
      new_usr = [uid + "@s3", decode_msg_arr[0], decode_msg_arr[1]]
      allowed_signers = open("allowed_signers", "a")
      allowed_signers.write(" ".join(new_usr) + "\n")
      allowed_signers.close()
      
      # send response to user
      self.send_response(200)
      self.send_header('Content-type', 'application/json')
      self.end_headers()
      report_str = "Uid registered! uid = " + uid
      self.wfile.write(report_str.encode("ascii"))
      print(report_str)
      
    elif action == "login":
      uid = path_arr[2]
      print("uid: ", uid)
      print("login")
      # get the current time
      cur_time = int(time.time())
      
      # check whether uid is valid, if not exits or format not match, then deny
      if uid not in valid_usr_name:
        self.send_response(403)
        self.end_headers()
        err_str = "Forbidden 403: invalid uid format"
        self.wfile.write(err_str.encode("ascii"))
        print(err_str)
        return
      if uid not in usrs:
        self.send_response(403)
        self.end_headers()
        err_str = "Forbidden 403: uid not registered"
        self.wfile.write(err_str.encode("ascii"))
        print(err_str)
        return
      
      # load message
      length = self.headers.get('content-length')
      data = self.rfile.read(int(length))
      decode_msg = data.decode('ascii')
      # decode_msg is the ssh signature
      # print("decode_msg")
      # print(decode_msg)
      
      # write the signature to the file
      sig_file = open("sig_file.sig", "w")
      sig_file.write(decode_msg)
      sig_file.close()
      
      flag = False
      # flag stores whether the varification passed
      for i in range(time_window):
        # this for loop is used to verify the signatures use time from current to (current - time_window + 1), if key is valid
        # and signatures are in the valid time window, then flag is turned to True.
        args = ["ssh-keygen", "-Y", "verify", "-f", "allowed_signers", "-I", uid+"@s3", "-n", "s3", "-s", "sig_file.sig"]
        # ssh-keygen -Y verify -f allowed_signers -I <uid>@s3 -n s3 -s sig_file.sig < time
        # reference: https://imzye.com/DevSecOps/signature-with-ssh-keys/
        output = subprocess.run(args, input=str(cur_time - i).encode("ascii"))
        # print("output of subprocess")
        # print(output)
        if output.returncode == 0:
          flag = True
          break
      
      if flag == False:
        self.send_response(403)
        self.end_headers()
        err_str = "Forbidden 403: Incorrect key or Overtime"
        self.wfile.write(err_str.encode("ascii"))
        print(err_str)
        return
      
      self.send_response(200)
      self.end_headers()
      report_str = "200: access granted, uid = " + uid
      self.wfile.write(report_str.encode("ascii"))
      print(report_str)
      
    else:
      self.send_response(400)
      self.end_headers()
      err_str = "Bad request 400: Unknown action"
      self.wfile.write(err_str)
      print(err_str)
      return
    

if __name__ == "__main__":        
  myServer = HTTPServer((hostName, serverPort), Server)
  print("Server launched http://%s:%s" % (hostName, serverPort))

  try:
    myServer.serve_forever()
  except KeyboardInterrupt:
    pass
  
  try:
    os.remove("allowed_signers")
    print("allowed_signers file removed")
  except:
    print("allowed_signers file not found")
  
  try:
    os.remove("sig_file.sig")
    print("sig_file.sig removed")
  except:
    print("sig_file.sig not found")
    

  myServer.server_close()
  print("Server terminated")
