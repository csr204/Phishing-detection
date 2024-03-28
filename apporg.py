import streamlit as st
from urllib.parse import urlparse
import re
from bs4 import BeautifulSoup
import requests
import tldextract
import whois
from googlesearch import search
from datetime import datetime
import pandas as pd
import joblib

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False
def load_model():
    model = joblib.load("forest.pkl")
    return model
model=load_model()


# sl.markdown(f"{style}",unsafe_allow_html=True)


title = 'Phishing Detection System'

# sl.markdown(f"<h1 style='text-align: center;'>{title}</h1>", unsafe_allow_html=True)

def check(url):
    # soup = BeautifulSoup(html, 'html.parser')
    # Length of URL
    length_url = len(url)

    # Length of hostname
    hostname = tldextract.extract(url).domain
    length_hostname = len(hostname)
    p_url=urlparse(url)
    # IP address (if available)
    ip=bool(re.match(r'\d+\.\d+\.\d+\.\d+', p_url.netloc))
    if ip==False:
        ip=0
    else:
        ip=1

    # Number of dots in the URL
    nb_dots = url.count('.')

    # Number of question marks in the URL
    nb_qm = url.count('?')

    # Number of equal signs in the URL
    nb_eq = url.count('=')

    # Number of slashes in the URL
    nb_slash = url.count('/')

    # Number of "www" in the URL
    nb_www = url.count('www')

    # Ratio of digits in the URL
    ratio_digits_url = sum(c.isdigit() for c in url) / len(url)

    # Ratio of digits in the hostname
    ratio_digits_host = sum(c.isdigit() for c in hostname) / len(hostname)

    # TLD in subdomain (1 if yes, 0 if no)
    tld_in_subdomain = int(tldextract.extract(url).subdomain.count('.') > 0)

    # Prefix or suffix in the hostname (1 if yes, 0 if no)
    prefix_suffix = int(bool(hostname.startswith('www.') or hostname.endswith('.com')))

    # Shortest word in the hostname
    shortest_word_host = min(len(word) for word in hostname.split('.'))
    try:
        response = requests.get(url)
    except:
        return 0    
    soup = BeautifulSoup(response.text, 'html.parser')
    # Longest words in the URL, raw HTML, and path
    try:
        longest_words_raw = max(len(word) for word in soup.get_text().split())
        longest_word_path = max(len(word) for word in url.split('/'))
    except:
        longest_words_raw = 0
        longest_word_path = 0
        
    # Phishing hints (1 if present, 0 if not)
    phish_hints_list = ['login', 'signin', 'verify', 'banking', 'password', 'security', 'update', 'support']
    phish_hints = 0
    for i in phish_hints_list:
        if i in url:
            phish_hints = i
            break
    # Number of hyperlinks on the page
    try:
        nb_hyperlinks = len(soup.find_all('a'))
    except:
        nb_hyperlinks = 0
    # Ratio of internal hyperlinks (pointing to the same domain)
    domain = tldextract.extract(url).registered_domain
    
    try:
        internal_links = [link.get('href') for link in soup.find_all('a') if tldextract.extract(link.get('href')).registered_domain == domain]
    except:
        internal_links = '0'
    if nb_hyperlinks!=0:
        ratio_intHyperlinks = len(internal_links) / nb_hyperlinks
    else:
        ratio_intHyperlinks = 0
    # Empty title tag (1 if yes, 0 if no)
    try:
        empty_title = int(bool(soup.title.string))
    except:
        empty_title=0
    
    try:    
        # Domain name in the title tag (1 if yes, 0 if no)
        domain_in_title = int(bool(domain in soup.title.string))
    except:
        domain_in_title = 0
    # Domain age (if available)
    try:
        whois = whois.whois(url)
        if 'creation_date' in whois:
            domain_age = (datetime.now().date() - whois['creation_date'].date()).days
        else:
            domain_age = 0
    except:
        domain_age=0

    # Google index status (1 if indexed, 0 if not)
    try :
        google_index = int('google.com' in requests.get(f"https://www.google.com/search?q={url}").text)
    except :
        google_index = 0
    # Page rank (if available)
    try:
        page_rank = google_pagerank(url)
    except:
        page_rank = 0
    
    
    input=pd.DataFrame(
            {
            'length_url' : [length_url],
            'length_hostname' : [length_hostname], 
            'ip':[ip], 
            'nb_dots':[nb_dots], 
            'nb_qm':[nb_qm], 
            'nb_eq':[nb_eq],
            'nb_slash':[nb_slash], 
            'nb_www':[nb_www], 
            'tld_in_subdomain':[tld_in_subdomain], 
            'prefix_suffix':[prefix_suffix], 
            'shortest_word_host':[shortest_word_host],
            'longest_words_raw':[longest_words_raw],
            'longest_word_path':[longest_word_path],
            'phish_hints':[phish_hints],
            'nb_hyperlinks':[nb_hyperlinks], 
            'empty_title':[empty_title],
            'domain_in_title':[domain_in_title], 
            'domain_age':[domain_age], 
            'google_index':[google_index], 
            'page_rank':[page_rank],
            'ratio_digits_url':[ratio_digits_url], 
            'ratio_digits_host':[ratio_digits_host],
            'ratio_intHyperlinks':[ratio_intHyperlinks], 
        }
        )    
    
    result = model.predict(input)
    print(result)
    return result
url=st.text_input("Enter url of the website",value="", max_chars=None, key=None, type="default", help=None, autocomplete=None, on_change=None, args=None, kwargs=None, placeholder="enter url of the website", disabled=False, label_visibility="visible")
# print(url)
if "https://" not in url:
    url="https://"+url
if st.button("check"):
    if len(url)==0 or is_valid_url(url)==False:
        st.write("Provide a valid link")
    else:
        result=check(url)
        if result==1:
            st.markdown('<span style="color:green">The website looks Safe</span>', unsafe_allow_html=True)
        else:
            st.markdown('<span style="color:red">The website looks Suspicious</span>', unsafe_allow_html=True)
            # st.write("suspicious")
