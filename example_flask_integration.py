"""
Example: How to use Brand Impersonation Detection in your Flask app
This shows how the detection is automatically integrated into your existing pipeline
"""

from pipeline.manager import PhishingDetectionPipeline

# Initialize the pipeline (brand detection is automatically included)
pipeline = PhishingDetectionPipeline()

# Example URLs to test
test_urls = [
    "https://www.youtube.com/watch",
    "https://youtubee-login.com/verify",
    "https://paypal.com",
    "https://paypal-login-secure.com/update",
]

print("=" * 80)
print("BRAND IMPERSONATION DETECTION - FLASK APP INTEGRATION EXAMPLE")
print("=" * 80)
print()

for url in test_urls:
    print(f"Testing: {url}")
    print("-" * 80)
    
    # Analyze URL through the pipeline
    result = pipeline.analyze(url)
    
    # Overall status
    print(f"Overall Status: {result['status']}")
    
    # Layer 2 (Domain Analysis) results - includes brand impersonation
    layer2 = result['layers']['layer2']
    print(f"Layer 2 Status: {layer2['status']}")
    print(f"Layer 2 Message: {layer2['message']}")
    
    # You can use this in your Flask route like this:
    """
    @app.route('/check', methods=['POST'])
    def check_url():
        url = request.form.get('url')
        result = pipeline.analyze(url)
        
        return jsonify({
            'status': result['status'],
            'layers': result['layers']
        })
    """
    
    print()

print("=" * 80)
print("INTEGRATION NOTES:")
print("=" * 80)
print("""
1. Brand impersonation detection is AUTOMATICALLY included in Layer 2
2. No changes needed to your Flask routes
3. Results are included in the 'layer2' section of the pipeline output
4. The detection adds detailed messages about brand impersonation attempts
5. Risk scoring is automatically integrated into the overall pipeline decision

Frontend Display Recommendation:
- If layer2 status is "Warning" and message contains "impersonation":
  * Show a prominent warning banner
  * Display the specific brand being impersonated
  * List the detection reasons (typosquatting, keywords, etc.)
  * Recommend user caution
""")
