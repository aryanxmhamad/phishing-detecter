from flask import Flask, request, jsonify, send_from_directory
import os

from analyzers.url_analyzer import analyze_url
from analyzers.email_analyzer import analyze_email
from analyzers.html_analyzer import analyze_html

app = Flask(__name__, static_folder="static")




# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    mode = data.get('mode', 'url')
    content = data.get('content', '').strip()

    if not content:
        return jsonify({"error": "No content provided"}), 400

    if mode == 'url':
        result = analyze_url(content)
    elif mode == 'email':
        result = analyze_email(content)
    elif mode == 'html':
        result = analyze_html(content)
    else:
        return jsonify({"error": "Invalid mode"}), 400

    return jsonify(result)


if __name__ == '__main__':
    os.makedirs('static', exist_ok=True)
    app.run(debug=True, port=5000)
