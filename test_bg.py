from app import create_app
from app.services.scan_service import get_pipeline
import time
import sys

print('creating app')
app = create_app('dev')
with app.app_context():
    pipeline = get_pipeline()
    print('Has sandbox:', pipeline.sandbox is not None)
    
    url = 'http://example.com'
    res = pipeline.analyze_fast(url)
    scan_id = res['scan_id']
    print(f'Fast scan done. scan_id={scan_id}')
    
    if pipeline.sandbox:
        pipeline.run_sandbox_background(url, scan_id)
        
    print('Waiting for background task...')
    for i in range(10):
        status = pipeline.get_sandbox_status(scan_id)
        print(f'Tick {i}, status: {status}')
        if status and status.get('done'):
            break
        time.sleep(2)
    print('Done.')
