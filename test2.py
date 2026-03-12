import threading
from playwright.sync_api import sync_playwright

def run_playwright():
    print('Starting sync_playwright...')
    try:
        with sync_playwright() as p:
            print('Playwright context open!')
    except Exception as e:
        print(f'Error: {e}')

t = threading.Thread(target=run_playwright)
t.start()
t.join(5)
print('Done')
