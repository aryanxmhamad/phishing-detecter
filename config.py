SUSPICIOUS_KEYWORDS = [
    'verify', 'account', 'suspended', 'urgent', 'login', 'update', 'confirm',
    'password', 'bank', 'paypal', 'amazon', 'apple', 'microsoft', 'google',
    'click here', 'act now', 'limited time', 'free', 'winner', 'congratulations',
    'security alert', 'unusual activity', 'billing', 'invoice', 'refund',
    'your account has been', 'dear customer', 'dear user', 'kindly', 'immediately'
]

PHISHING_URL_PATTERNS = [
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',           # IP address as host
    r'(paypal|amazon|apple|google|microsoft|bank).*\.(ru|cn|tk|ml|ga|cf|gq|pw|xyz|top|club)',  # brand + bad tld
    r'@',                                               # @ in URL (redirect trick)
    r'-{3,}',                                           # many hyphens
    r'(login|signin|secure|account|update|verify).*\.(com|net|org)\.',  # subdomain abuse
    r'bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|is\.gd|cli\.gs|buff\.ly',   # URL shorteners
    r'[a-z0-9]{30,}',                                  # very long random string
]

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq',
    '.pw', '.xyz', '.top', '.club',
    '.ru', '.cn', '.cc', '.ws',
    '.click', '.link', '.work',
    '.live', '.cam', '.zip',
    '.review', '.country', '.stream',
    '.download', '.support', '.monster',
    '.buzz', '.space', '.rest',
    '.fit', '.quest', '.lol',
    '.icu', '.shop'
]
LEGITIMATE_DOMAINS = [

    # Google
    'google.com',
    'gmail.com',
    'youtube.com',
    'googleusercontent.com',

    # Microsoft
    'microsoft.com',
    'office.com',
    'live.com',
    'outlook.com',

    # Apple
    'apple.com',
    'icloud.com',

    # Amazon
    'amazon.com',
    'aws.amazon.com',

    # Meta
    'facebook.com',
    'instagram.com',
    'whatsapp.com',
    'threads.net',

    # Others
    'paypal.com',
    'github.com',
    'gitlab.com',
    'linkedin.com',
    'reddit.com',
    'netflix.com',
    'dropbox.com',
    'cloudflare.com',
    'mozilla.org',
    'wikipedia.org',
    'stackoverflow.com',
    'discord.com',
    'zoom.us',
    'adobe.com',
    'openai.com'
]
