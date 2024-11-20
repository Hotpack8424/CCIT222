from flask import Flask, request, jsonify
import os
import joblib
import xgboost as xgb
from urllib.parse import urlparse
import socket
import requests
import dns.resolver
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import time
import re
import whois
import tldextract
import pandas as pd

# Flask 앱 초기화
app = Flask(__name__)

# XGBoost 모델 로드
model_path = './Phishing_model_02.pkl'  # 모델 경로
loaded_model = joblib.load(model_path)

# 크롤링 및 분석 기능 구현

# URL 유효성 검사 함수
def is_valid_url(url):
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return False
        domain = result.netloc
        if len(domain) > 253:
            return False
        if re.search(r'[^\x00-\x7F]', url):
            return False
        if '..' in domain:
            return False
        return True
    except ValueError:
        return False

# URL 특수 문자 제거 함수
def clean_url(url):
    return re.sub(r'[^\x00-\x7F]+', '', url)

# 도메인 만료일과 생성일 확인 함수
def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        expiration_date = w.expiration_date
        registrant_name = w.get('name', 'Unknown')

        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        if creation_date is None or expiration_date is None:
            return None, None, None, registrant_name

        domain_age_days = (expiration_date - creation_date).days
        return creation_date, expiration_date, domain_age_days, registrant_name

    except Exception as e:
        return None, None, None, 'Unknown'

# JavaScript 난독화 확인 함수
def is_obfuscated_script(script_content):
    return bool(re.search(r"[a-zA-Z$_]\s*=\s*function\s*\(.*\)", script_content))

# URL 스킴(프로토콜) 확인 함수
def ensure_url_scheme(url):
    return 'https://' + url if not url.startswith(('http://', 'https://')) else url

# 동적 iframe 크롤링
def crawl_website_with_selenium(url):
    try:
        # 셀레니움으로 브라우저 실행
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)
        driver.get(url)
        
        # 자바스크립트가 실행된 후의 DOM을 가져옴
        page_source = driver.page_source
        
        # BeautifulSoup을 사용하여 HTML 파싱
        soup = BeautifulSoup(page_source, 'html.parser')

        # iframe 태그 분석 (동적으로 추가된 iframe 포함)
        iframes = driver.find_elements(By.TAG_NAME, 'iframe')
        hidden_iframes = sum(1 for iframe in iframes if iframe.get_attribute('style') == 'display:none;' or iframe.get_attribute('width') == '0')

        # 콘텐츠 크기 계산 (HTML 크기)
        content_size = len(page_source)

        # 브라우저 종료
        driver.quit()

        return hidden_iframes, content_size

    except Exception as e:
        return None, None

# 웹사이트 동적 분석 (AJAX, 쿠키 설정, 스크립트 실행 등 확인)
def analyze_website(url):
    try:
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)
        dynamic_analysis = {
            'redirection_count': 0,
            'external_domain_requests': 0,
            'malicious_file_downloads': 0,
            'script_execution_count': 0,
            'iframe_present': False,
            'ajax_calls': 0,
            'cookie_settings': 0
        }

        driver.set_page_load_timeout(10)
        driver.get(url)

        # iFrame 감지
        iframes = driver.find_elements(By.TAG_NAME, 'iframe')
        dynamic_analysis['iframe_present'] = len(iframes) > 0

        # AJAX 호출 감지
        dynamic_analysis['ajax_calls'] = len(driver.find_elements(By.XPATH, "//script[contains(text(), 'XMLHttpRequest')]"))

        # 쿠키 설정 감지
        if 'document.cookie' in driver.page_source:
            dynamic_analysis['cookie_settings'] += 1

        # 스크립트 실행 감지
        dynamic_analysis['script_execution_count'] = len(driver.find_elements(By.TAG_NAME, 'script'))

    except Exception as e:
        print(f"Error analyzing {url}: {e}")
    finally:
        driver.quit()

    return dynamic_analysis

# 메인 크롤러 함수
def crawl_website(url):
    # URL 유효성 검사 및 특수 문자 제거
    url = clean_url(url)
    if not is_valid_url(url):
        return None

    try:
        url = ensure_url_scheme(url)

        # 리디렉션을 따라가지 않고 리디렉션 발생 여부 기록
        try:
            response = requests.get(url, headers=headers, timeout=15, allow_redirects=False)
        except UnicodeError as e:
            return None

        redirect_count = 0
        final_url = url

        if 300 <= response.status_code < 400:
            final_url = response.headers.get('Location', url)
            redirect_count = 1  # 리디렉션 발생한 것으로 간주

        response.raise_for_status()  # HTTP 에러 코드 체크

        soup = BeautifulSoup(response.text, 'html.parser')

        parsed_url = tldextract.extract(url)
        domain = parsed_url.domain + '.' + parsed_url.suffix

        # IP 주소 확인
        ip_address = socket.gethostbyname(domain)

        # 도메인 연령 및 등록자 정보 확인
        creation_date, expiration_date, domain_age, registrant_name = get_domain_age(domain)

        # 서브 도메인 수
        subdomain_count = len(parsed_url.subdomain.split('.')) if parsed_url.subdomain else 0

        # iframe 태그 분석 및 콘텐츠 크기 확인
        hidden_iframe_count, content_size = crawl_website_with_selenium(url)

        # 스크립트 태그 개수 및 난독화 비율 계산
        script_tags = soup.find_all('script')
        total_script_length = sum(len(script.text) for script in script_tags)
        obfuscated_script_length = sum(len(script.text) for script in script_tags if is_obfuscated_script(script.text))

        obfuscation_ratio = (obfuscated_script_length / total_script_length) if total_script_length > 0 else 0
        is_obfuscated = any(is_obfuscated_script(script.text) for script in script_tags)
        script_count = len(script_tags)

        dynamic_analysis = analyze_website(url)

        result = {
            'URL': url,
            'IP Address': ip_address,
            'Domain Age (days)': domain_age,
            'Subdomain Count': subdomain_count,
            'Hidden Iframe Count': hidden_iframe_count,
            'Total Script Length': total_script_length,
            'Obfuscated Script Length': obfuscated_script_length,
            'Obfuscation Ratio': obfuscation_ratio,
            'Is Obfuscated': is_obfuscated,
            'Script Count': script_count,
            'Redirect Count': redirect_count,
            'Final URL': final_url,
            'AJAX Call Count': dynamic_analysis['ajax_calls']
        }

        # 데이터 전처리 후 예측
        df_single_result = pd.DataFrame([result])
        df_processed = preprocess_data(df_single_result)

        # XGBoost 모델 로드 및 예측
        dmatrix = xgb.DMatrix(df_processed)
        prediction = loaded_model.predict(dmatrix)

        blocked = bool(prediction[0] > 0.5)  # 0.5 이상의 확률이면 피싱으로 간주
        return 'Phishing site' if blocked else 'Safe site'

    except Exception as e:  
        return None


# 전처리 함수 정의
def preprocess_data(df):
    # 불필요한 열 제거
    columns_to_drop = ['URL', 'IP Address', 'Final URL']
    df = df.drop(columns=columns_to_drop, errors='ignore')

    # 불리언 값을 1과 0으로 변환
    bool_columns = ['Is Obfuscated']
    df[bool_columns] = df[bool_columns].astype(int)

    # 특정 열의 NaN 처리
    nan_columns = ['Hidden Iframe Count', 'Total Script Length', 'Domain Age (days)']
    df[nan_columns] = df[nan_columns].apply(pd.to_numeric, errors='coerce')

    return df

# API 엔드포인트 정의
@app.route('/analyze', methods=['POST'])
def analyze_url():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    # 크롤링 및 분석 함수 호출
    result_status = crawl_website(url)
    if result_status == 'Phishing site':
        return jsonify({'result': 'Phishing site'}), 200
    elif result_status == 'Safe site':
        return jsonify({'result': 'Safe site'}), 200
    else:
        return jsonify({'error': 'Error analyzing URL'}), 500

# API 실행
if __name__ == '__main__':
    app.run(debug=True)
