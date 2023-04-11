import flask
from flask import Flask, request, jsonify
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
import re
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
import requests

# Define the Flask app
app = Flask(__name__)

# Load the data
data = pd.read_csv('malicious_phish.csv')
data.drop_duplicates(inplace=True)
le = LabelEncoder()
data['type'] = le.fit_transform(data['type'])

# Train the model
X = data.drop(['type'], axis=1)
y = data['type']
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
rf = RandomForestClassifier(n_estimators=100, max_features='sqrt', random_state=42)
rf.fit(X_scaled, y)

# Define the helper functions
def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        return 1
    else:
        return 0

def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 1
    else:
        return 0




def cerificate(url):
    api_url = f"https://crt.sh/?output=json&domain={url}"
    response = requests.get(api_url)
    if response.status_code == 200:
        results = response.json()
        if len(results) > 0:
            return 1
    return 0

@app.route('/cerificate')
def check_certificate():
    url = request.args.get('url')
    has_certificate = cerificate(url)
    if has_certificate:
        return "Certificate found"
    else:
        return "No certificate found"



# Define the API route
@app.route('/predict', methods=['POST'])
def predict():
    # Get the input data from the request
    data = request.get_json(force=True)
    url = data['url']

    # Preprocess the input data
    is_abnormal = abnormal_url(url)
    has_shortening_service = shortening_service(url)
    has_certificate = cerificate(url)

    # Make the prediction
    input_data = [[is_abnormal, has_shortening_service, has_certificate]]
    input_data_scaled = scaler.transform(input_data)
    prediction = rf.predict(input_data_scaled)

    # Return the prediction as a JSON response
    output = {'prediction': le.inverse_transform(prediction)[0]}
    return jsonify(output)
