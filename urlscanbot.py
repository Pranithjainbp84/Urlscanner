from telethon import TelegramClient, events
import re
import requests
import csv
import pandas as pd

# Replace with your own API details
API_ID = '27944145'  # Get this from https://my.telegram.org/apps
API_HASH = '669a4a6b97530be26832ae4bf1d40ef1'
BOT_TOKEN = '8125290746:AAExNaYE-lSIeed_FxRPInhZjFPp0gyQSXs'  # API Token from BotFather

# Create Telegram bot client
client = TelegramClient('bot_session', API_ID, API_HASH).start(bot_token=BOT_TOKEN)

# Function to scan URLs with VirusTotal
def scan_virustotal(url):
    params = {'apikey': 'fff46419e2e3b81e12649cb53d2d4f225584a98981739974eb31b4f8e32cceea', 'resource': url}
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
    
    if response.json().get('positives', 0) > 2:
        return "⚠️ Malicious Link Detected!"
    return "✅ Link is safe."

# Function to save results to CSV
def save_to_csv(url, status):
    with open("scanned_urls.csv", "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([url, status])

# Function to check if a URL has been scanned before
def check_previous_scans(url):
    try:
        df = pd.read_csv("scanned_urls.csv")
        if url in df.values:
            return "⚠️ This link has been flagged as malicious before!"
    except FileNotFoundError:
        pass
    return None

# Function to scan email headers with VirusTotal (just for email headers as text)
def scan_email_header(header_data):
    params = {'apikey': 'fff46419e2e3b81e12649cb53d2d4f225584a98981739974eb31b4f8e32cceea'}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files={'file': header_data})
    
    if response.json().get('response_code') == 1:
        return "✅ Header is safe."
    return "⚠️ Potential phishing detected."

# Bot's behavior: When a new message comes in
@client.on(events.NewMessage)
async def handle_message(event):
    message = event.text
    # Extract URLs from the message
    urls = re.findall(r'https?://\S+', message)
    
    for url in urls:
        # Check if URL has been previously flagged
        previous_result = check_previous_scans(url)
        if previous_result:
            await event.reply(previous_result)
        else:
            # Scan the URL using VirusTotal
            result = scan_virustotal(url)
            save_to_csv(url, result)
            await event.reply(f"{result}: {url}")

# Start the bot
print("Bot is running...")
client.run_until_disconnected()
