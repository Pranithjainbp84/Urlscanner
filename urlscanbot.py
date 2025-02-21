from telethon import TelegramClient, events
import re
import requests
import pandas as pd
import os

# Replace with your own API details
API_ID = '27944145'  # API_ID must be an integer
API_HASH = '669a4a6b97530be26832ae4bf1d40ef1'  # API_HASH is a string
BOT_TOKEN = '8125290746:AAExNaYE-lSIeed_FxRPInhZjFPp0gyQSXs'  # BOT_TOKEN is a string

# Create Telegram bot client
client = TelegramClient('bot_session', API_ID, API_HASH).start(bot_token=BOT_TOKEN)

# Function to scan URLs with VirusTotal
def scan_virustotal(url):
    params = {'apikey': 'fff46419e2e3b81e12649cb53d2d4f225584a98981739974eb31b4f8e32cceea', 'resource': url}
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
    if response.json().get('positives', 0) > 2:
        return "⚠️ Malicious Link Detected!"
    return "✅ Link is safe."

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
@client.on(events.NewMessage(pattern='/scan (https?://\S+)'))
async def scan_url(event):
    url = event.pattern_match.group(1)
    result = scan_virustotal(url)
    await event.reply(result)

# /history Command
@client.on(events.NewMessage(pattern='/history'))
async def history(event):
    try:
        df = pd.read_csv("scanned_urls.csv")
        history_text = "Previously Scanned URLs:\n"
        for index, row in df.iterrows():
            history_text += f"{row['URL']} - {row['Status']}\n"
        await event.reply(history_text)
    except FileNotFoundError:
        await event.reply("No scan history available.")

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

# Run the bot
print("Bot is running...")
client.run_until_disconnected()
