from telethon import TelegramClient, events
import re
import requests
import pandas as pd
import os
import csv
from datetime import datetime

# Initialize CSV file
def init_csv():
    if not os.path.exists("scanned_urls.csv"):
        with open("scanned_urls.csv", "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["URL", "Status", "Timestamp"])

# Replace with your own API details
API_ID = 'YOUR_API_ID'  # API_ID as integer
API_HASH = 'YOUR_API_HASH'  # API_HASH is a string
BOT_TOKEN = 'YOUR_BOT_TOKEN'  # BOT_TOKEN is a string

# Create Telegram bot client
client = TelegramClient('bot_session', API_ID, API_HASH).start(bot_token=BOT_TOKEN)

# Domain blacklist checker
def check_domain_blacklist(domain):
    # Known malicious domain patterns and TLDs
    blacklisted_patterns = [
        'phishing', 'scam', 'malware', 'hack',
        'security', 'login', 'account', 'verify',
        'suspicious', 'prize', 'winner'
    ]
    suspicious_tlds = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top']
    
    domain = domain.lower()
    
    # Check for blacklisted patterns
    for pattern in blacklisted_patterns:
        if pattern in domain:
            return f"⚠️ Domain contains suspicious pattern: {pattern}"
            
    # Check TLD
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        return "⚠️ Domain uses suspicious TLD"
        
    return None

async def enhanced_security_check(url):
    try:
        # Check domain reputation
        domain = url.split('/')[2]
        
        # DNS checks
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, 'A')
            ip = answers[0].to_text()
            
            # Check if IP is in known blacklists
            if ip in ['127.0.0.1', '0.0.0.0']:  # Example blacklist
                return "Suspicious IP detected"
        except:
            pass
            
        return None
    except Exception as e:
        print(f"Error in security check: {e}")
        return None

def scan_virustotal(url):
    try:
        # Check domain blacklist first
        domain = url.split('/')[2]
        blacklist_result = check_domain_blacklist(domain)
        
        params = {'apikey': 'YOUR_VIRUSTOTAL_KEY', 'resource': url}
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
        json_response = response.json()
        
        positives = json_response.get('positives', 0)
        scans = json_response.get('scans', {})
        
        # Check for phishing specifically
        phishing_detected = any(
            scan.get('result', '').lower() in ['phishing', 'malicious', 'malware', 'suspicious']
            for scan in scans.values()
        )
        
        if phishing_detected or positives > 0:
            result = "⚠️ Warning: Potentially Malicious/Phishing Link Detected!"
        else:
            result = "✅ Link appears safe"
            
        details = f"(Detection rate: {positives}/{len(scans) if scans else 'N/A'})"
        full_result = f"{result} {details}"
        
        # Save to CSV
        with open("scanned_urls.csv", "a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([url, full_result, datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
        
        return full_result
    except Exception as e:
        print(f"Error scanning URL: {e}")
        return "❌ Error scanning URL"

# Command Handlers

# /start Command
@client.on(events.NewMessage(pattern='/start'))
async def start(event):
    await event.reply("Hello! I am your Malicious Link Scanner Bot. Send me a link, and I will check if it's safe.")

# /help Command
@client.on(events.NewMessage(pattern='/help'))
async def help(event):
    help_text = (
        "I can help you detect malicious links! Here's what I can do:\n"
        "/start - Introduction\n"
        "/scan <URL> - Scan a specific URL for safety\n"
        "/history - View previously scanned URLs\n"
        "/status - Check the status of the bot\n" 
        "/contact - Contact the developer\n"
        "/about - About the bot\n"
    )
    await event.reply(help_text)

# /scan Command
@client.on(events.NewMessage(pattern='/scan'))
async def scan_url(event):
    try:
        message = event.message.text
        if len(message.split()) < 2:
            await event.reply("Please provide a URL to scan. Usage: /scan <URL>")
            return
            
        url = message.split()[1]
        if not url.startswith(('http://', 'https://')):
            await event.reply("Please provide a valid URL starting with http:// or https://")
            return
            
        result = scan_virustotal(url)
        await event.reply(f"Scanning: {url}\nResult: {result}")
    except Exception as e:
        await event.reply(f"Error processing URL: {str(e)}")

# /history Command
@client.on(events.NewMessage(pattern='/history'))
async def history(event):
    try:
        if not os.path.exists("scanned_urls.csv"):
            await event.reply("No scan history available yet. Use /scan to check URLs.")
            return
            
        try:
            df = pd.read_csv("scanned_urls.csv")
        except pd.errors.EmptyDataError:
            await event.reply("No scan history available yet. Use /scan to check URLs.")
            return
        except pd.errors.ParserError:
            await event.reply("Error: History file is corrupted. Use /reset to clear history.")
            return
            
        if df.empty:
            await event.reply("No scan history available yet. Use /scan to check URLs.")
            return
            
        history_text = "📋 Recently Scanned URLs:\n\n"
        for index, row in df.tail(10).iterrows():
            try:
                url = str(row['URL']).strip()
                status = str(row['Status']).strip()
                timestamp = str(row['Timestamp']).strip() if 'Timestamp' in row else "N/A"
                
                if url and status:
                    history_text += f"🔗 {url}\n"
                    history_text += f"📊 Status: {status}\n"
                    history_text += f"⏰ {timestamp}\n"
                    history_text += "---------------\n"
            except KeyError:
                continue
        
        if history_text == "📋 Recently Scanned URLs:\n\n":
            await event.reply("No valid scan history available.")
            return
            
        await event.reply(history_text)
    except Exception as e:
        print(f"Error in history command: {e}")
        await event.reply("An error occurred while fetching scan history. Please try again later.")

# /status Command
@client.on(events.NewMessage(pattern='/status'))
async def status(event):
    await event.reply("The bot is running and ready to scan links.")

# /reset Command
@client.on(events.NewMessage(pattern='/reset'))
async def reset(event):
    try:
        os.remove("scanned_urls.csv")
        await event.reply("Scan history has been cleared.")
    except FileNotFoundError:
        await event.reply("No history to clear.")

# /contact Command
@client.on(events.NewMessage(pattern='/contact'))
async def contact(event):
    contact_info = "For support, reach us at: Pranithjainbp84@gmail.com"
    await event.reply(contact_info)

# /about Command
@client.on(events.NewMessage(pattern='/about'))
async def about(event):
    about_text = (
        "This is the Malicious Link Scanner Bot.\n"
        "Developed by Pranith Jain.\n"
        "It scans links for malicious content using various APIs like VirusTotal and others."
    )
    await event.reply(about_text)



# Initialize and run the bot
init_csv()
print("Bot is running...")
client.run_until_disconnected()
