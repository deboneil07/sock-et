# central_server.py
from flask import Flask, request, jsonify

app = Flask(__name__)

# Dictionary to store ngrok addresses
clients = {}

@app.route('/register', methods=['POST'])
def register_client():
    data = request.get_json()
    client_id = data['client_id']
    address = data['ngrok_address']
    
    # Register or update the client ngrok address
    clients[client_id] = address
    return jsonify({"message": "Client registered successfully!"}), 200

@app.route('/get_peer/<client_id>', methods=['GET'])
def get_peer(client_id):
    # Return the ngrok address of the peer client (if any)
    peer_id = [cid for cid in clients if cid != client_id]
    
    if peer_id:
        return jsonify({"peer_address": clients[peer_id[0]]}), 200
    else:
        return jsonify({"message": "No peers available."}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
