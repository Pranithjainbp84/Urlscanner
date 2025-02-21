UrlScanner Bot
UrlScanner Bot is a Telegram bot that helps detect malicious links in messages. It checks URLs using the VirusTotal API and alerts users if a link is dangerous.

Features
URL Scanning: Automatically checks links in messages for safety.
Scan History: Keeps track of previously scanned links.
Commands:
/start: Start the bot.
/scan <URL>: Manually scan a URL.
/history: View scanned URLs.
/reset: Clear the scan history.
/help: See available commands.
Requirements
Python 3.6+
Libraries:
telethon
requests
pandas
Install the required libraries by running:

bash
Copy
pip install telethon requests pandas
Setup
Create a Telegram Bot:

Open Telegram and search for BotFather.
Create a bot and get the Bot Token.
Get Your API Keys:

Sign up for a VirusTotal account and get the API Key.
Configure the Bot:

Download or clone this repository.
Replace YOUR_API_ID, YOUR_API_HASH, YOUR_BOT_TOKEN, and YOUR_VIRUSTOTAL_KEY in the urlscanbot.py file with your details.
Run the Bot:

bash
Copy
python urlscanbot.py
How to Use
Start the bot: Type /start in your chat to begin.
Scan URLs: Send any message with a URL, and the bot will check if it's safe.
Manually scan: Use /scan <URL> to check a specific link.
View scan history: Use /history to see previous scans.
Clear history: Use /reset to clear the history.
License
This project is licensed under the MIT License.

Contact
For support or questions, reach out to:
Email: support@example.com

Enjoy using UrlScanner Bot! 🚀

