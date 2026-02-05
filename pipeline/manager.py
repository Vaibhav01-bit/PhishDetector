from .layers import Layer1_Blacklist, Layer2_Domain, Layer3_SSL, Layer4_ML_Model, Layer5_Behavioral, SAFE, WARNING, PHISHING
from .sandbox import SandboxAnalyzer
from .forensics import ForensicAnalyzer

class PhishingDetectionPipeline:
    def __init__(self, enable_sandbox=True):
        self.forensics = ForensicAnalyzer()
        self.l1 = Layer1_Blacklist()
        self.l2 = Layer2_Domain()
        self.l3 = Layer3_SSL()
        self.l4 = Layer4_ML_Model()
        self.l5 = Layer5_Behavioral()
        self.sandbox = SandboxAnalyzer() if enable_sandbox else None

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
                print(f"Sandbox error: {e}")
                results['sandbox'] = {'success': False, 'error': str(e), 'scan_id': None}
        
        return self._finalize(final_status, results, forensics_data)

    def _finalize(self, final_status, results, forensics_data):
        return {
            'status': final_status,
            'layers': results,
            'forensics': forensics_data
        }
