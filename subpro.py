import subprocess

result = subprocess.run(
    ["ls", "-l"],
    cwd="/home/govind/Downloads/Python",
    capture_output=True,
    text=True
)

print(result.stdout)


################################ 

result = subprocess.run(
    ["ls", "split.py"],
    # ["ls", "main.py"],
    cwd="/home/govind/Downloads/Python",
    capture_output=True,
    text=True
)

if result.returncode == 0:
    print("File exists")
else:
    print("File does NOT exist")

###################################


result = subprocess.run(
    ["python3", "split.py"],
    cwd="/home/govind/Downloads/Python",
    capture_output=True,
    text=True
)

print("OUTPUT:")
print(result.stdout)

print("ERROR:")
print(result.stderr)


#################################


try:
    subprocess.run(
        ["python3", "split.py"],
        cwd="/home/govind/Downloads/Python",
        check=True
    )
    print("Script ran successfully")
except subprocess.CalledProcessError:
    print("Script failed")


###################################



# WHEN WORK WITH GIT & GITHUB

result = subprocess.run(
    ["git", "status"],
    cwd="/home/govind/Downloads/Python",
    capture_output=True,
    text=True
)

print(result.stdout)

##################################



# # Step 1: list files
p1 = subprocess.run(
    ["ls"],
    cwd="/home/govind/Downloads/Python",
    capture_output=True,
    text=True
)

# # Step 2: grep .py
p2 = subprocess.run(
    ["grep", ".py"],
    input=p1.stdout,
    capture_output=True,
    text=True
)

# Step 3: count
p3 = subprocess.run(
    ["wc", "-l"],
    input=p2.stdout,
    capture_output=True,
    text=True
)

print("Total .py files:", p3.stdout.strip()) # using strip for remove extra space


#################################



result = subprocess.run(
    "ls | grep .py | wc -l",
    cwd="/home/govind/Downloads/Python",
    shell=True,
    capture_output=True,
    text=True
)

print("Total .py files:", result.stdout.strip())



################################


with open("files.txt", "w") as f: # f is file object to store open file 
    subprocess.run(
        ["ls", "-l"],
        cwd="/home/govind/Downloads/Python",
        stdout=f,
        text=True
    )

###############################


try:
    subprocess.run(
        ["sleep", "10"],
        cwd="/home/govind/Downloads/Python",
        timeout=3
    )
except subprocess.TimeoutExpired:
    print("Command took too long, killed")


###############################

subprocess.run(
    ["awk", "{print $2}", "split.py"],
    capture_output=True,
    text=True
)
