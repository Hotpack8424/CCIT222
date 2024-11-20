# Phishing Detection API

This API allows you to analyze a URL to detect phishing sites or safe sites using a pre-trained XGBoost model.

## Installation

1. Clone this repository:
    ```bash
    git clone https://github.com/yourusername/phishing-detection-api.git
    cd phishing-detection-api
    ```

2. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3. Run the Flask server:
    ```bash
    python app.py
    ```

## API Endpoints

### POST `/analyze`
Analyze a URL to detect phishing or safe sites.

**Request Body:**
```json
{
    "url": "https://example.com"
}
