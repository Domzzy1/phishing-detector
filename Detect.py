from urllib.parse import urlparse
import tldextract

# List of known suspicious TLDs (make sure you have these from previous code)
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "biz", "info", "club", "online",
    "website", "trade", "loan", "win", "app", "work", "live", "shop", "click",
    "rest", "fun", "fit", "pro", "rocks"
}

# List of allowed social media domains (from previous code)
ALLOWED_SOCIAL_MEDIA_DOMAINS = {
    "facebook.com", "zoom.com", "twitter.com", "instagram.com", "linkedin.com", 
    "slack.com", "chatgbt.com", "mynafa.com", "wave.com", "apsinternational.com",
    "vidmate.com", "messenger.com", "threads.com", "discord.com", "google.com", 
    "icloud.com", "youtube.com", "tiktok.com", "snapchat.com", "reddit.com", 
    "pinterest.com", "tumblr.com", "afrixapp.com", "sendcash.com", "twitch.tv", 
    "whatsapp.com", "telegram.org", "medium.com", "quora.com", "github.com", 
    "gitlab.com", "bitbucket.org", "vk.com", "weibo.com", "flickr.com", "meetup.com", 
    "mix.com", "soundcloud.com"
}

# List of typo-squatted domains (from previous code)
TYPO_SQUATTED_DOMAINS = {
    "faceboook.com", "faecbook.com", "fcebook.com", "facebok.com",
    "zo0m.com", "zomm.com", "twittter.com", "twiiter.com", "twiter.com", "twtter.com",
    "instgram.com", "instagrm.com", "instagramm.com", "1nstagram.com", "linkedln.com",
    "llinkedin.com", "lnkedIn.com", "linkdin.com", "slak.com", "slcak.com", "sllack.com",
    "chatgpt.com", "chatgbt.ai", "chat-gbt.com", "mynnafa.com", "mynafa.co", "mynafa.net",
    "waave.com", "waveapp.com", "apsinternational.net", "apsinterational.com", 
    "vidmatte.com", "vidmat.com", "vidmte.com", "mesenger.com", "mssenger.com", 
    "messnger.com", "threds.com", "threadds.com", "threadz.com", "disscord.com", 
    "discrod.com", "discor.com", "gogle.com", "goggle.com", "goog1e.com", "iclod.com", 
    "icluod.com", "iclouds.com", "youtub.com", "you-tube.com", "yotube.com", "tik-tok.com",
    "tikto.com", "tiktoik.com", "snapcaht.com", "snapchatt.com", "snaphcat.com", "reditt.com",
    "reddi.com", "reddittt.com", "pintrest.com", "pintrst.com", "pinterestt.com", "tumbr.com",
    "tmblr.com", "tumblir.com", "afrixap.com", "afriixapp.com", "sendcashh.com", "sendcah.com",
    "twtch.tv", "twittch.tv", "whatsap.com", "whatsapp.net", "whatsappp.com", "telegarm.org",
    "telegramm.org", "tellegram.org", "medim.com", "mediumm.com", "quorra.com", "qu0ra.com",
    "gitbub.com", "githb.com", "gittub.com", "gitllab.com", "gtilab.com", "gittlab.com", 
    "bitbuckt.org", "bitbuket.org", "vk.cm", "vk-com.com", "webio.com", "weebio.com", 
    "flicker.com", "fliickr.com", "meetp.com", "meettup.com", "mixx.com", "miix.com",
    "soundclod.com", "soundcoud.com" "reddittt.com", "pinterestt.com", "tumblrr.com", "googlle.com", 
    "vime0.com", "facebookk.com", "linkedinn.com", "amazn.com", 
    "paypal-verification.com", "facebook-security.com", "you-tub3.com", 
    "microsofft.com", "accounts-google.com", "yahooo.com", "bankofamerica-security.com",
    "googl-verify.com", "paymentupdate-paypal.com", "micro-soft.com", 
    "securedropbox.com", "logn-facebook.com", "passwrd-recovery.com",
    "accunt-update.com", "pass-reset-twitter.com", "pass-chng-twitter.com",
    "login-update-yahoo.com", "account-security-verify.com", "account-alerts-twitter.com",
}

# List of suspicious subdomains (from previous code)
SUSPICIOUS_SUBDOMAINS = {
    "login", "secure", "account", "verify", "update", "webmail", "support", "billing", 
    "helpdesk", "customer", "client", "dashboard", "portal", "signin", "auth", "authorize", 
    "banking", "service", "recovery", "password", "confirm", "activation", "unlock", "id", 
    "admin", "management", "redirect", "validate", "secure-login", "safe", "checkout", 
    "order", "pay", "payment", "invoice", "transaction", "notifications", "alert", "alerts", 
    "messages", "profile", "settings", "subscription", "upgrade", "free", "promo", "offers", 
    "bonus", "gift", "rewards", "survey", "contest", "download", "access", "token", "user", 
    "myaccount", "email", "cloud", "drive", "share", "storage", "upload", "cdn", "static", 
    "delivery", "files", "doc", "docs", "vpn", "proxy", "remote", "connect", "gate", "gateway", 
    "checkout-secure", "secure-server", "security-check", "identity-verification", "crypto", 
    "wallet", "eth", "btc", "paypal", "venmo", "bank", "finance", "crypto-wallet" "secure-login", "account-recovery", "login-update", "reset-password", 
    "payment-processing", "login-verification", "offer-claiming", 
    "verify-account", "confirm-payment"  "login-secure", "account-update", 
    "security-verify", "email-verification", "auth-login", "verify-identity", 
    "user-authentication", "account-suspension", "payment-confirmation", 
    "reset-password-now", "phishing-warning", "claim-prize", "support-verify", 
    "alert-login", "change-password", "access-alert", "service-updates"
}


def analyze_url(url):
    parsed_url = urlparse(url)  # Parse the URL
    ext = tldextract.extract(url)  # Extract domain components

    domain = f"{ext.domain}.{ext.suffix}"  # Get the domain (e.g., "facebook.com")
    subdomain = ext.subdomain  # Extract subdomain
    path = parsed_url.path  # Extract path (everything after domain)
    query_params = parsed_url.query  # Extract query parameters

    print(f"\n🔬 Analysis for: {domain}")

    # Check if the domain is a known social media domain
    if domain in ALLOWED_SOCIAL_MEDIA_DOMAINS:
        print("✅ Trusted Social Media Domain")
        return  # No need for further analysis

    # Suspicious TLD check
    if ext.suffix in SUSPICIOUS_TLDS:
        print("• Suspicious TLD: ✅")

    # Typosquatting check
    if domain in TYPO_SQUATTED_DOMAINS:
        print("• Known Typosquat warned: 🚩")

    # Excessive Subdomains check
    subdomain_count = subdomain.count(".") + 1 if subdomain else 0
    if subdomain_count > 2:
        print("• Excessive Subdomains: ✅")

    # Suspicious Subdomain check
    for sub in SUSPICIOUS_SUBDOMAINS:
        if sub in subdomain:
            print("• Suspicious Subdomain: 🚩")

    # Suspicious Query Parameters check
    if any(param in query_params for param in ["id", "token", "login", "auth"]):
        print("• Suspicious Query Parameters: 🚩")

    # If any red flags are detected, mark as phishing
    if any(keyword in url.lower() for keyword in ["login", "signin", "verify", "security"]):
        print("\n❌ PHISHING RISK DETECTED")
    else:
        print("\n✅ No clear threats found")


# Main program loop
print("\n=== URL PHISHING DETECTOR ===\n")

while True:
    user_input = input("Enter URL (or 'q' to quit): ").strip()
    if user_input.lower() == "q":
        break
    analyze_url(user_input)
