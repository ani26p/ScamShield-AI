import joblib, math, re
from urllib.parse import urlparse

art = joblib.load('models/model.pkl')
scaler = art['scaler']
model  = art['model']
FEATS  = art['feature_names']
KEYWORDS = ['login','verify','bank','secure','update','account','password','confirm','signin','paypal']

def full_url_features(url):
    url = str(url).strip()
    try:
        parsed = urlparse(url if '://' in url else 'http://' + url)
        domain = parsed.netloc or ''
    except: domain = ''
    domain = domain.split(':')[0]
    n = len(url)
    freq = {}
    for ch in url: freq[ch] = freq.get(ch,0)+1
    entropy = -sum((c/n)*math.log2(c/n) for c in freq.values()) if n else 0
    return {
        'url_length': n,
        'num_dots': url.count('.'),
        'has_at': int('@' in url),
        'has_hyphen': int('-' in domain),
        'has_suspicious_kw': int(any(k in url.lower() for k in KEYWORDS)),
        'url_entropy': round(entropy,4),
        'is_ip_address': int(bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain))),
        'domain_length': len(domain),
        'has_https': int(url.lower().startswith('https')),
    }

lines = []
# Compare what training legit data looked like vs real browsing URLs
pairs = [
    # (training URL, real URL from browser, label)
    ('https://youtube.com',       'https://www.youtube.com/',                                          'LEGIT'),
    ('https://hotstar.com',       'https://www.hotstar.com/in/onboarding/profile?ref=/in/home',        'LEGIT'),
    ('https://google.com',        'https://www.google.com/',                                           'LEGIT'),
    ('https://amazon.com',        'https://www.amazon.com/s?k=laptop&crid=123456',                     'LEGIT'),
]

for train_url, real_url, expected in pairs:
    ft = full_url_features(train_url)
    fr = full_url_features(real_url)
    lines.append(f"=== {expected}: {real_url[:60]} ===")
    lines.append(f"  FEATURE          TRAINING VALUE    REAL URL VALUE    MATCH?")
    for feat in FEATS:
        tv = ft[feat]
        rv = fr[feat]
        match = 'OK' if tv == rv else f'DIFF ({tv} vs {rv})'
        lines.append(f"  {feat:<22} {str(tv):<18} {str(rv):<18} {match}")
    # Predict real URL
    X = [[fr[f] for f in FEATS]]
    Xs = scaler.transform(X)
    lbl = int(model.predict(Xs)[0])
    prob = model.predict_proba(Xs)[0]
    lines.append(f"  PREDICTION = {'PHISHING' if lbl==1 else 'LEGIT'}  phish_prob={prob[1]:.4f}")
    lines.append("")

with open('diag_root_cause.txt','w',encoding='utf-8') as f:
    f.write('\n'.join(lines))
print("done")
