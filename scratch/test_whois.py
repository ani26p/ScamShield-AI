import sys
import os
from pathlib import Path

# Add backend to path to import extractor
backend_path = Path(r"d:\COLLAGE\4th SEM\(2) CSET210 - (DTI) Design thinking & Innovation\ScamShield AI (New test)\backend")
sys.path.append(str(backend_path))

try:
    from app.feature_extractor import _lookup_creation_date, _rdap_domain_age, _pywhois_domain_age
    
    test_domains = ["google.com", "microsoft.com", "github.com"]
    
    for dom in test_domains:
        print(f"Testing {dom}...")
        
        rdap = _rdap_domain_age(dom)
        print(f"  RDAP: {rdap}")
        
        whois_res = _pywhois_domain_age(dom)
        print(f"  WHOIS: {whois_res}")
        
        final = _lookup_creation_date(dom)
        print(f"  Final: {final}")
        print("-" * 20)

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
