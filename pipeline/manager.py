from .layers import Layer1_Blacklist, Layer2_Domain, Layer3_SSL, Layer4_ML_Model, Layer5_Behavioral, SAFE, WARNING, PHISHING

class PhishingDetectionPipeline:
    def __init__(self):
        self.l1 = Layer1_Blacklist()
        self.l2 = Layer2_Domain()
        self.l3 = Layer3_SSL()
        self.l4 = Layer4_ML_Model()
        self.l5 = Layer5_Behavioral()

    def analyze(self, url):
        results = {}
        
        # Layer 1: Blacklist
        status, message = self.l1.check(url)
        results['layer1'] = {'status': status, 'message': message}
        if status == PHISHING:
            return self._finalize(PHISHING, results)

        # Layer 2: Domain Analysis
        status, message = self.l2.check(url)
        results['layer2'] = {'status': status, 'message': message}
        
        # Layer 3: SSL Check
        status, message = self.l3.check(url)
        results['layer3'] = {'status': status, 'message': message}
        
        # Layer 4: ML Model
        status, message = self.l4.check(url)
        results['layer4'] = {'status': status, 'message': message}
        
        # Layer 5: Behavioral Analysis
        status, message = self.l5.check(url)
        results['layer5'] = {'status': status, 'message': message}

        # Aggregation Logic
        # If ML (Layer 4) says Phishing, it's very likely Phishing.
        if results['layer4']['status'] == PHISHING:
             return self._finalize(PHISHING, results)
             
        # If SSL is invalid (Phishing), it's Phishing
        if results['layer3']['status'] == PHISHING:
            return self._finalize(PHISHING, results)
            
        # If behavioral or domain has multiple warnings, or just any warning
        warnings = [r for r in results.values() if r['status'] == WARNING]
        if len(warnings) > 0:
            return self._finalize(WARNING, results)
            
        return self._finalize(SAFE, results)

    def _finalize(self, final_status, results):
        return {
            'status': final_status,
            'layers': results
        }
