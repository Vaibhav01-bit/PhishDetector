from .layers import Layer1_Blacklist, Layer2_Domain, Layer3_SSL, Layer4_ML_Model, Layer5_Behavioral, SAFE, WARNING, PHISHING
from .sandbox import SandboxAnalyzer
from .forensics import ForensicAnalyzer
from .sandbox_utils import generate_scan_id
from datetime import datetime
import threading
import os
import json

class PhishingDetectionPipeline:
    def __init__(self, enable_sandbox=True):
        self.forensics = ForensicAnalyzer()
        self.l1 = Layer1_Blacklist()
        self.l2 = Layer2_Domain()
        self.l3 = Layer3_SSL()
        self.l4 = Layer4_ML_Model()
        self.l5 = Layer5_Behavioral()
        self.sandbox = SandboxAnalyzer() if enable_sandbox else None

    def analyze_fast(self, url):
        """
        FAST PATH: Runs forensics + layers 1-5 only (no sandbox).
        Returns preliminary verdict immediately with a scan_id so the
        caller can launch the sandbox asynchronously and poll for results.
        """
        scan_id = generate_scan_id()
        results = {}

        # 0. Forensic / redirect analysis
        forensics_data = self.forensics.analyze(url)
        target_url = forensics_data['final_url']

        redirect_count = forensics_data.get('redirect_count', 0)
        is_shortener  = forensics_data.get('is_shortener', False)

        if redirect_count > 3:
            results['forensics_check'] = {'status': WARNING, 'message': f'Excessive redirects ({redirect_count}). Risk of obfuscation.'}
        elif is_shortener:
            results['forensics_check'] = {'status': SAFE, 'message': 'Shortened URL detected. Final destination analyzed.'}
        elif redirect_count > 0:
            results['forensics_check'] = {'status': SAFE, 'message': f'Redirects followed ({redirect_count}). Final destination analyzed.'}
        else:
            results['forensics_check'] = {'status': SAFE, 'message': 'Direct link. No redirects.'}

        # Layers 1-5 (no sandbox)
        status, message = self.l1.check(target_url)
        results['layer1'] = {'status': status, 'message': message}
        if status == PHISHING:
            return self._finalize_fast(PHISHING, results, forensics_data, scan_id)

        status, message = self.l2.check(target_url)
        results['layer2'] = {'status': status, 'message': message}

        status, message = self.l3.check(target_url)
        results['layer3'] = {'status': status, 'message': message}
        if status == PHISHING:
            return self._finalize_fast(PHISHING, results, forensics_data, scan_id)

        status, message = self.l4.check(target_url)
        results['layer4'] = {'status': status, 'message': message}
        if status == PHISHING:
            return self._finalize_fast(PHISHING, results, forensics_data, scan_id)

        status, message = self.l5.check(target_url)
        results['layer5'] = {'status': status, 'message': message}

        warnings = [r for r in results.values() if r.get('status') == WARNING]
        final_status = WARNING if warnings else SAFE

        return self._finalize_fast(final_status, results, forensics_data, scan_id)

    def _finalize_fast(self, final_status, results, forensics_data, scan_id):
        """Package the fast result and persist it so polling can find it."""
        data = {
            'status': final_status,
            'layers': results,
            'forensics': forensics_data,
            'scan_id': scan_id,
            'preliminary': True  # flag: sandbox not yet run
        }
        # Persist fast result so /scan/status can enrich it later
        try:
            path = os.path.join('static', 'sandbox_results', f'{scan_id}_fast.json')
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f'Warning: could not save fast result: {e}')
        return data

    def run_sandbox_background(self, url, scan_id):
        """
        Launch sandbox analysis in a background daemon thread.
        ALL work happens in the thread — never blocks the HTTP response.
        """
        # Load the fast result snapshot now (file already written)
        fast_path = os.path.join('static', 'sandbox_results', f'{scan_id}_fast.json')
        try:
            with open(fast_path, 'r', encoding='utf-8') as f:
                fast_data = json.load(f)
            layers_snapshot = fast_data.get('layers', {})
            final_status   = fast_data.get('status', SAFE)
            forensics_snap = fast_data.get('forensics', {})
        except Exception:
            layers_snapshot = {}
            final_status   = SAFE
            forensics_snap = {}

        def _run():
            # Default to failure so status file is always written
            status_data = {'done': True, 'success': False, 'scan_id': scan_id}
            try:
                sandbox_result = self.sandbox.analyze(url, scan_id=scan_id)

                combined = dict(layers_snapshot)
                combined['sandbox'] = sandbox_result

                if sandbox_result.get('success') and sandbox_result.get('scan_id'):
                    self.sandbox.save_full_results(scan_id, {
                        'status': final_status,
                        'layers': combined,
                        'forensics': forensics_snap
                    })

                status_data = {
                    'done': True,
                    'success': sandbox_result.get('success', False),
                    'screenshot_path': sandbox_result.get('screenshot_path'),
                    'scan_id': scan_id,
                    'has_login_form': sandbox_result.get('has_login_form', False),
                    'has_password_field': sandbox_result.get('has_password_field', False),
                    'error': sandbox_result.get('error')
                }
            except Exception as e:
                import traceback
                print(f'[Sandbox BG error] {traceback.format_exc()}')
                status_data = {'done': True, 'success': False, 'error': str(e), 'scan_id': scan_id}

            try:
                status_path = os.path.join('static', 'sandbox_results', f'{scan_id}_status.json')
                with open(status_path, 'w', encoding='utf-8') as f:
                    json.dump(status_data, f, indent=2)
                print(f'[Sandbox] status written: success={status_data["success"]}')
            except Exception as ex:
                print(f'Warning: could not save sandbox status: {ex}')

        t = threading.Thread(target=_run, daemon=True)
        t.start()

    def get_sandbox_status(self, scan_id):
        """
        Read the status sentinel written by run_sandbox_background.
        Returns None if not yet done.
        """
        status_path = os.path.join('static', 'sandbox_results', f'{scan_id}_status.json')
        if not os.path.exists(status_path):
            return None
        try:
            with open(status_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return None

    def analyze(self, url):
        results = {}
        
        # 0. Forensic Analysis (Pre-scan)
        # We analyze redirects first to scan the FINAL destination, which is safer and more accurate.
        forensics_data = self.forensics.analyze(url)
        target_url = forensics_data['final_url']
        
        # Feature 2: URL Shortener & Redirects
        redirect_count = forensics_data.get('redirect_count', 0)
        is_shortener = forensics_data.get('is_shortener', False)
        
        if redirect_count > 3:
             results['forensics_check'] = {'status': WARNING, 'message': f'Excessive redirects detected ({redirect_count}). Risk of obfuscation.'}
        elif is_shortener:
             # We mark as SAFE because we successfully resolved it, but we inform the user.
             results['forensics_check'] = {'status': SAFE, 'message': 'Shortened URL detected. Final destination analyzed.'}
        elif redirect_count > 0:
             results['forensics_check'] = {'status': SAFE, 'message': f'Redirects followed ({redirect_count}). Final destination analyzed.'}
        else:
             results['forensics_check'] = {'status': SAFE, 'message': 'Direct link. No redirects.'}
        
        # Layer 1: Blacklist
        status, message = self.l1.check(target_url)
        results['layer1'] = {'status': status, 'message': message}
        if status == PHISHING:
            return self._finalize(PHISHING, results, forensics_data)

        # Layer 2: Domain Analysis
        status, message = self.l2.check(target_url)
        results['layer2'] = {'status': status, 'message': message}
        
        # Layer 3: SSL Check
        status, message = self.l3.check(target_url)
        results['layer3'] = {'status': status, 'message': message}
        
        # Layer 4: ML Model
        status, message = self.l4.check(target_url)
        results['layer4'] = {'status': status, 'message': message}
        
        # Layer 5: Behavioral Analysis
        status, message = self.l5.check(target_url)
        results['layer5'] = {'status': status, 'message': message}

        # Aggregation Logic
        final_status = SAFE
        
        if results['layer4']['status'] == PHISHING:
             return self._finalize(PHISHING, results, forensics_data)
             
        if results['layer3']['status'] == PHISHING:
            return self._finalize(PHISHING, results, forensics_data)
            
        warnings = [r for r in results.values() if r['status'] == WARNING]
        if len(warnings) > 0:
            final_status = WARNING
        else:
            final_status = SAFE
            
        # Sandbox Analysis
        if self.sandbox:
            try:
                sandbox_result = self.sandbox.analyze(url)
                results['sandbox'] = sandbox_result
                
                # Update full results with forensics
                if sandbox_result.get('success') and sandbox_result.get('scan_id'):
                    self.sandbox.save_full_results(sandbox_result['scan_id'], {
                        'status': final_status,
                        'layers': results,
                        'forensics': forensics_data
                    })
                    
            except Exception as e:
                import traceback
                error_msg = f"Sandbox error: {str(e)}\n{traceback.format_exc()}"
                print(error_msg)
                with open("sandbox_error.log", "a") as f:
                    f.write(f"[{datetime.now()}] {error_msg}\n")
                results['sandbox'] = {'success': False, 'error': str(e), 'scan_id': None}
        
        return self._finalize(final_status, results, forensics_data)

    def _finalize(self, final_status, results, forensics_data):
        return {
            'status': final_status,
            'layers': results,
            'forensics': forensics_data
        }
