from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/', methods=['POST'])
def receive_data():
    data = request.get_json()
    return jsonify({"status": "success", "received": data}), 200

if __name__ == "__main__":
    app.run(debug=True)
