import requests
import json

# URL of the running Flask application
url = "http://127.0.0.1:8000/collect"

# Test data
data = [
    {
        "index": "bucket1",
        "events": [
            {"_time": "2024-12-03T12:00:00", "msg": "Event 1"},
            {"_time": "2024-12-03T12:10:00", "msg": "Event 2"}
        ]
    },
    {
        "index": "bucket2",
        "events": [
            {"_time": "2024-12-03T13:00:00", "msg": "Event A"}
        ]
    }
]

# Send the POST request
response = requests.post(url, data=json.dumps(data), headers={"Content-Type": "application/json"})

# Print the response
print(f"Status Code: {response.status_code}")
print(f"Response Text: {response.text}")
