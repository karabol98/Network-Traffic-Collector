import pyshark
import binascii
import json

# Path to the pcap file
pcap_file = 'capture_202502051514.pcap'

# Capture only POST requests to /index
cap = pyshark.FileCapture(pcap_file, display_filter='http.request.method == "POST" && http.request.uri contains "/index"')

request_count = 0

for packet in cap:
    try:
        http_layer = packet.http
        if hasattr(http_layer, 'file_data'):
            # Extract and decode the hex data
            hex_data = http_layer.file_data.replace(':', '')
            json_bytes = binascii.unhexlify(hex_data)
            json_str = json_bytes.decode('utf-8')

            # Parse JSON
            json_data = json.loads(json_str)

            # Save to a distinct file
            request_count += 1
            filename = f'request_{request_count}.json'
            with open(filename, 'w') as json_file:
                json.dump(json_data, json_file, indent=4)

            print(f'Saved {filename}')

    except (json.JSONDecodeError, AttributeError, binascii.Error) as e:
        print(f"Skipping packet due to error: {e}")
        continue

cap.close()
