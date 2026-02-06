
import sys
import os
import traceback

# Add current directory to path so we can import 'pipeline'
sys.path.append(os.getcwd())

from pipeline.sandbox import SandboxAnalyzer

def log(msg):
    with open("debug_log.txt", "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def test_sandbox():
    try:
        if os.path.exists("debug_log.txt"):
            os.remove("debug_log.txt")
            
        log("Initializing SandboxAnalyzer...")
        sandbox = SandboxAnalyzer()
        log("SandboxAnalyzer initialized.")

        url = "https://www.google.com"
        log(f"Analyzing {url}...")
    
        result = sandbox.analyze(url)
        log("\nAnalysis Result:")
        log(str(result))
        
        if result.get('success'):
            log("\nSUCCESS: Sandbox analysis completed.")
        else:
            log(f"\nFAILURE: {result.get('error')}")
            
    except Exception as e:
        log(f"\nCRITICAL EXCEPTION during analysis: {e}")
        log(traceback.format_exc())

if __name__ == "__main__":
    test_sandbox()
