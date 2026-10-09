import subprocess
def unsafe():
    command = input()
    subprocess.run(command, shell=True)
