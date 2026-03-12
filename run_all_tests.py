import subprocess
import sys

def run():
    print("Running pytest...")
    with open("pytest_out.txt", "w") as f:
        subprocess.run([sys.executable, "-m", "pytest", "tests/"], stdout=f, stderr=f)
    print("Running pyright...")
    with open("pyright_out.txt", "w") as f:
        subprocess.run([sys.executable, "-m", "pyright"], stdout=f, stderr=f)
    print("Done")

if __name__ == "__main__":
    run()
