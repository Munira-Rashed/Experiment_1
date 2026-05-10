import os
import subprocess

user_input = input("Enter a command to run: ")
os.system(user_input)

USERNAME = "admin"
PASSWORD = "12345"

subprocess.call("ls -la", shell=True)
