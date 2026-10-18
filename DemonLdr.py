from havoc import RegisterCallback, PayloadConsoleWrite, ScriptResource
import base64
import requests

CALLBACK_UDRL_GENERATE  = 0x1
SPEC_FILE               = ScriptResource("loader.spec")
CAPAB_FILE              = ScriptResource("bin/loader.x64.o")
CPL_ENDPOINT            = "http://127.0.0.1:60060/link"

def OnDemonGenerate(filename, arch, payload) -> bytes:    
    try:

        if arch == "x86":
            PayloadConsoleWrite("Error", "loader only support x64")
            return None

        
        response = requests.post(CPL_ENDPOINT, json={
            "action": "link",
            "params": {
                "spec": SPEC_FILE,
                "file": CAPAB_FILE
            },
            "env": {
                "$DLL": bytes(payload).hex()
            }
        })

        response.raise_for_status()    
        data = response.json()
        if data.get("success") is True:
            if data.get("message") != "":
                PayloadConsoleWrite("Info", data.get("message"))

            loader = base64.b64decode(data["output_b64"])

            PayloadConsoleWrite("Info", f"PIC size: {len(loader)}")

            return loader
        else:
            PayloadConsoleWrite("Error", f"Failure {data.get('context')}:\n{data.get('message')}")
    
    except requests.exceptions.RequestException as e:
        PayloadConsoleWrite("Error", f"Crystal Palace server is down: {e}")

    return None

RegisterCallback(CALLBACK_UDRL_GENERATE, OnDemonGenerate)
