from flask import Flask, request

app = Flask(__name__)

@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def handle_request(path):
    method = request.method

    headers = request.headers

    body = request.get_data(as_text=True)

    print(f"Method: {method}")
    print(f"Path: /{path}")
    print("Headers:")
    # print(headers)
    for header, value in headers.items():
        print(f"{header}: {value}")
    print(f"Body: {body}")
    print("***********************")
    return "OK"

if __name__ == '__main__':
    app.run(port=3307)