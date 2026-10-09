import subprocess
def safe():
    command = "printf fixture"
    subprocess.run(command, shell=True)
