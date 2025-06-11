import streamlit as st
import re #python regex module
from urllib.parse import urlparse  #helps to parse the url into different components



SUSPICIOUS_KEYWORDS = ['login', 'verify', 'update', 'secure', 'account', 'bank', 'signin', 'webscr','password','urgent','link','expired','payment','immediate','action']
SUSPICIOUS_TLDS = ['.ru', '.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.buzz','.zip']

 
# Custom HTML + CSS
#1.TITLE
st.markdown(
    """
    <style>

    .neon-title {
        text-align: left;
        font-size: 40px;
        color: #DEAC80;
        font-weight: bold;
        margin-bottom: 20px;
        font-family: Georgia, serif;
        transition: text-shadow 0.3s ease;
        display: flex;
        align-items: center;
        gap: 10px;
       
    }
    .neon-title:hover {
        text-shadow:
            0 0 5px #00FFAB,
            0 0 10px #00FFAB,
            0 0 20px #00FFAB,
            0 0 40px #00FFAB;
        color: #00FFA0;
        cursor:grab;
    }
    .neon-title svg {
        fill:#DEAC80;
        transition: fill 0.3s ease;
    }
    .neon-title:hover svg {
        fill: #00FFA0;
    }
    </style>

    <div class="neon-title">
        <!-- Icon next to title -->
        <svg xmlns="http://www.w3.org/2000/svg" height="30" viewBox="0 0 24 24" width="30">
            <path d="M20 4H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2zm0 2-8 5-8-5h16zm0 12H4V8l8 5 8-5v10z"/>
        </svg>
        Phishing Email Detector
    </div>
    """, 
    unsafe_allow_html=True
)

#2.Greeting text

st.markdown(
    """
    <style>
    .Greeting-text {
        font-family: Georgia, serif;
        font-size: 20px;
        color: #DEAC80;
        margin-bottom: 20px;
        user-select: none;
        margin-left:30px
    }
    </style>

    <div class="Greeting-text">
       👋 Hey! Time to see if that message is trying to phish you
    </div>
    """,
    unsafe_allow_html=True
)

#3. Pasting instruction:
st.markdown(
    """
    <style>
    .custom-label {
        font-size: 18px;
        color:  #DEAC80;
        font-family: Georgia, serif;
        margin-top:10px;
        margin-bottom: 8px;
        display: block;
    }
    </style>
    <label class="custom-label">Please paste your email below and click <strong>'Scan'</strong></label>
    """,
    unsafe_allow_html=True
)




#a method to check whether the url is legit or suspicious
def is_suspicious_url(url):
    parsed=urlparse(url)
    domain=parsed.netloc.lower()
    path=parsed.path.lower()
    count=0
  

    #1.is the domain an ip address(eg:193.176.0.1)?
    if re.match(r'\d+\.\d+\.\d+\.\d+',domain):
       count+=2
    
    
     # 2. Suspicious top-level domains
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
           count+=2
           break 

     # 3. Too many subdomains
    if domain.count('.')>3:
        count+=1

    return count

def check_suspicious_keywords_near_urls(email_text, urls):
    score = 0
    email_text_lower = email_text.lower()

    for url in urls:
        url_lower = url.lower()
        url_pos = email_text_lower.find(url_lower)

        # Check if URL itself is suspicious
        url_score = is_suspicious_url(url)
        score += url_score

        # Check keywords within 50 chars before or after the URL
        start = max(0, url_pos - 50)
        end = url_pos + len(url_lower) + 50
        surrounding_text = email_text_lower[start:end]

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in surrounding_text:
                score += 3  # higher weight if keyword near suspicious URL
                break  # count only once per URL

    return score

def check_suspicious_keywords_alone(email_text):
    count = 0
    email_text_lower = email_text.lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in email_text_lower:
            count += 1  # low weight for keywords alone

    return count



email_body = st.text_area("⬇️", height=300)

if st.button("SCAN"):
    urls = re.findall(r'https?://[^\s]+', email_body)
    total_count=0

    total_count += check_suspicious_keywords_near_urls(email_body,urls)

    if urls:
        for url in urls:
            total_count += check_suspicious_keywords_alone(email_body)

    #final decision based on count
    if total_count >=4:
        st.error('⚠️ Alert! This email looks suspicious and may not be legitimate-Please verify before acting')
    else:
        st.success('✅ Yay! You can go ahead. This email looks safe and legit.')

#fix email body text , give margin color to the box , fix scan button just the color and the margin color do not go to hover for scan  button because it already good