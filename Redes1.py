import socket
import json


def parse_HTTP_message(http: bytes) -> dict: #Parseamos usando diccionariosxd
    HEAD, LOL, BODY = http.partition(b"\r\n\r\n") #particionamos en el corte de linea y el body
    lines = HEAD.decode().split("\r\n")
    start_line = lines[0]
    goateds = start_line.split(" ")
    method = goateds[0]
    path = goateds[1]
    version = goateds[2]
    headers = {}
    for linea in lines[1:]: #por cada linea de headers ponemos nombre y valor en el diccionario
        if ":" in linea:
            nombre, valor = linea.split(":", 1)
            headers[nombre.strip()] = valor.strip()
    return {
        "method": method,
        "path": path,
        "version": version,
        "headers": headers,
        "body": BODY
    } #retornamos el diccionario con los datos parseados


def create_HTTP_message(status_code=200, status_text="OK", headers=None, body=b""): #crea un mensaje http
    if headers is None: #fixea bug
        headers = {}
    if isinstance(body, str): #encodeamos
        body = body.encode()
    headers.setdefault("Content-length", str(len(body)))
    headers.setdefault("Connection", "close")

    start_line = f"HTTP/1.1 {status_code} {status_text}\r\n" 
    header_lines = "".join(f"{k}: {v}\r\n" for k, v in headers.items()) #concatenamos todos los headers
    response = start_line.encode() + header_lines.encode() + b"\r\n" + body
    return response


def build_HTTP_request(parsed_msg: dict) -> bytes: #se reconstruye el mensaje http a partir del diccionario
    start_line = f"{parsed_msg['method']} {parsed_msg['path']} {parsed_msg['version']}\r\n" #armamos
    header_lines = "".join(f"{k}: {v}\r\n" for k, v in parsed_msg['headers'].items())
    return start_line.encode() + header_lines.encode() + b"\r\n" + parsed_msg['body'] #juntamos todo y encodeamos


def receive_http_message(conn, buff_size, timeout=None): #recibre un mensaje http de un socket
    if timeout is not None: #el timeout lo usamos para el server de destino (aveces se bugeaba)
        conn.settimeout(timeout)

    data = b""
    while b"\r\n\r\n" not in data: #aqui la funcion recibe el mensaje hasta el corte de linea
        try:
            chunk = conn.recv(buff_size) 
        except socket.timeout:
            return data
        if not chunk:
            return data
        data += chunk

    head, _, body_so_far = data.partition(b"\r\n\r\n")

    content_length = None
    for line in head.decode(errors="replace").split("\r\n")[1:]:
        if line.lower().startswith("content-length:"):
            content_length = int(line.split(":", 1)[1].strip())
            break
            # buscamos el content-lenght para saber cuando body falta
    if content_length is not None:
        while len(body_so_far) < content_length: #completamos hasta el content-length
            try:
                chunk = conn.recv(buff_size)
            except socket.timeout:
                break
            if not chunk:
                break
            body_so_far += chunk
        return head + b"\r\n\r\n" + body_so_far

    while True: #sin content-length, recibimos hasta que el socket se cierre o se acabe el timeout
        try:
            chunk = conn.recv(buff_size)
        except socket.timeout:
            break
        if not chunk:
            break
        body_so_far += chunk

    return head + b"\r\n\r\n" + body_so_far


def get_destination(msgparsed): #saca host y puerto del mensaje http parseado
    host_header = msgparsed["headers"].get("Host")
    if host_header is None:
        return None, None # sin host

    if ":" in host_header: #host:puerto
        host, port = host_header.split(":", 1)
        port = int(port)
    else: #si no usamosun default de 80
        host = host_header
        port = 80

    return host, port


def load_json(path): #si 
    with open(path) as file:
        return json.load(file)


def is_blocked(request_path, blocked_domains): #True si esta en los bloqueados
    for entry in blocked_domains:
        if entry in request_path:
            return True
    return False


def replace_forbidden_words(body: bytes, forbidden_words) -> bytes: #reemplaza las prohibidas
    for entry in forbidden_words:
        for word, replacement in entry.items():
            body = body.replace(word.encode(), replacement.encode())
    return body


def process_response(raw_response: bytes, forbidden_words, nombre_usuario) -> bytes:
    head, sep, body = raw_response.partition(b"\r\n\r\n")
    if not sep:
        return raw_response  # no venía bien formado, asique retornamos igual

    new_body = replace_forbidden_words(body, forbidden_words) #cambiamos las prohibidas

    header_lines = head.decode(errors="replace").split("\r\n")
    start_line = header_lines[0]
    new_headers = [start_line]
    for line in header_lines[1:]: #hacemos un content lenth nuevo y agregamos el nombre del usuario
        if line.lower().startswith("content-length:"):
            continue
        new_headers.append(line)
    new_headers.append(f"Content-Length: {len(new_body)}")
    new_headers.append(f"X-ElQuePregunta: {nombre_usuario}")

    new_head = "\r\n".join(new_headers)
    return new_head.encode() + b"\r\n\r\n" + new_body


def build_blocked_response(): #creamos un http con la pagina bloqueada con la foto
    body_html = """<html>
<body>
<h1>403 - Blocked Domain</h1>
<img src="/gato_bloqueado.png" alt="imagen no cargada">
</body>
</html>"""
    return create_HTTP_message(
        status_code=403,
        status_text="Forbidden",
        headers={"Content-Type": "text/html"},
        body=body_html
    )


def build_image_response(image_path): #creamos la parte del http la foto del gato emperador
    with open(image_path, "rb") as img_file:
        image_bytes = img_file.read()

    return create_HTTP_message(
        status_code=200,
        status_text="OK",
        headers={"Content-Type": "image/png"},
        body=image_bytes
    )


IP_VM = "localhost"
PORT = 8000

BUFF_SIZE = 50 #este se uso para probar los distintos buffers de las pruebas


if __name__ == "__main__":

    try:
        with open("test.json") as file:
            data = json.load(file)
            nombre_usuario = data.get("nombre", "JosephMonett")
    except FileNotFoundError:
        nombre_usuario = "JosephMonett"
    # nombre para el header si no encuentra el json
    config = load_json("prohibido.json")
    blocked_domains = config.get("blocked", [])
    forbidden_words = config.get("forbidden_words", [])

    new_socket_address = (IP_VM, PORT)
    print(f"SocketTest --- botsintg --- Usando buffer de {BUFF_SIZE}")
    #hacemos sockets orientados conexion
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.bind(new_socket_address)
    proxy_socket.listen(2)
    print(f"SocketQueue --- Skivisi --- en {IP_VM}:{PORT}")

    while True:
        client_socket, client_address = proxy_socket.accept()
        #espera que se conecte un cliente
        print("conectando desde:", client_address)

        recv_message = receive_http_message(client_socket, BUFF_SIZE, timeout=5)
        print("Request Recibida:", recv_message)

        if not recv_message:
            client_socket.close()
            continue
            #el cliente no mando nada xd, cierra conexion
        msgparsed = parse_HTTP_message(recv_message)
        print("Request Parseada:", msgparsed)

        if "/gato_bloqueado.png" in msgparsed["path"]: #foto para la pagina bloqueada
            img_response = build_image_response("gatoemperador.png")
            client_socket.send(img_response)
            client_socket.close()
            continue

        host, port = get_destination(msgparsed)

        if not host: #si no hay un header, entonces cortamos conexion (no tiene destino)
            client_socket.close()
            continue

        if msgparsed["method"] == "CONNECT": #si intenta conectarse usando HTTPS, entonces cortamos conexion
            print(f"CONNECT no soportado, ignorando: {host}")
            client_socket.close()
            continue

        print(f"Reenviando a: {host}:{port}")


        


        if is_blocked(msgparsed["path"], blocked_domains): #logica del bloqueo de paginas
            print(f"BLOQUEADO: {msgparsed['path']}")
            blocked_response = build_blocked_response()
            client_socket.send(blocked_response)
            client_socket.close()
            continue

        msgparsed["headers"]["X-ElQuePregunta"] = nombre_usuario #inyectamos este header.
        request_to_send = build_HTTP_request(msgparsed)
        #conexion al servidor de destino
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server_socket.connect((host, port))
            server_socket.send(request_to_send)
            response = receive_http_message(server_socket, BUFF_SIZE, timeout=2)
        except OSError as e:
            print(f"No se pudo conectar a {host}:{port} -> {e}")
            client_socket.close()
            continue
        finally:
            server_socket.close()
        

        response = process_response(response, forbidden_words, nombre_usuario) #censuramos prohibidas y agregamos header


        head_test,lul,  body_test = response.partition(b"\r\n\r\n")
        print(f"TAMANIO HEAD: {len(head_test)} bytes")
        print(f"TAMANIO BODY: {len(body_test)} bytes")
        #DEBUGS

        client_socket.send(response)
        client_socket.close()