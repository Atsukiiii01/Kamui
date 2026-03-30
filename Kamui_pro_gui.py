import threading
import subprocess
import random
import time
import FreeSimpleGUI as F
import threading
import asyncio
import logging
from kamui_bridge import AsyncKamuiBridge
from kamui_intel import run_pipeline


# ---------------------------------------------------------
# 1. The Async Background Engine
# ---------------------------------------------------------
# This spins up a dedicated thread to handle all the heavy 
# async network and subprocess I/O without freezing your GUI.
kamui_loop = asyncio.new_event_loop()

def start_background_loop(loop: asyncio.AbstractEventLoop):
    asyncio.set_event_loop(loop)
    loop.run_forever()

engine_thread = threading.Thread(target=start_background_loop, args=(kamui_loop,), daemon=True)
engine_thread.start()

# ---------------------------------------------------------
# 2. Bridge Initialization
# ---------------------------------------------------------
bridge = AsyncKamuiBridge(
    pipeline_func=run_pipeline,
    api_key="", # Highly recommended to put your NVD API key here
    min_score=7.0,
    output_dir="kamui_output"
)

active_scan = None

# ---------------------------------------------------------
# 3. GUI Button Triggers
# ---------------------------------------------------------
def execute_scan(cmd_list):
    """Call this when the user clicks 'INITIATE SCAN'"""
    global active_scan

    def safe_print(msg):
        # NOTE: If using Tkinter, you must use root.after() to update text widgets safely.
        # e.g., root.after(0, lambda: text_box.insert("end", msg + "\n"))
        print(msg) 

    def on_complete(results):
        safe_print("\n[+] Intelligence Pipeline Complete.")
        # Process and display your JSON results here

    def on_error(err_msg):
        safe_print(f"\n[!] FATAL: {err_msg}")

    # We must submit the scan to the background async loop
    def _dispatch_scan():
        global active_scan
        active_scan = bridge.run_scan(
            cmd_list=cmd_list,
            output_cb=safe_print,
            complete_cb=on_complete,
            error_cb=on_error
        )

    # Thread-safe submission
    kamui_loop.call_soon_threadsafe(_dispatch_scan)


def cancel_scan():
    """Call this when the user clicks 'CANCEL'"""
    global active_scan
    if active_scan:
        async def _cancel():
            logger = logging.getLogger("kamui.ui")
            await active_scan.cancel(logger)
            
        asyncio.run_coroutine_threadsafe(_cancel(), kamui_loop)

F.theme('Black')

# This class does absolutely nothing useful i was trying something bit later on forgot. but i decided to keep it....
class Useless_Data:
    def __init__(self):
        self.data = [i for i in range(100)]
    def scramble(self):
        random.shuffle(self.data)
        return self.data[0]

# Init junk
junk = Useless_Data()
junk.scramble()
# -------------------------------

# SIGNATURE
sig_txt = "[ made by atsukiiii01 ]"

# LAYOUT 
# Keys are now random numbers/letters donno why i did...
layout = [
    [F.Text(":: GHOST PROTOCOL ::", text_color="#00ff00", font=("Helvetica", 16)), F.Push(), F.Text(sig_txt, text_color="grey")],
    [F.Text("-" * 60, text_color="grey")],
    
    [F.Text("TARGET >"), F.Input(key="k_tgt", size=(45, 1))],
    
    # Nested lists 
    [F.Frame(" SCAN ", [[
        F.Radio("Stealth", "g1", default=True, key="r1"),
        F.Radio("Connect", "g1", key="r2"),
        F.Radio("UDP", "g1", key="r3"),
        F.Radio("Loud", "g1", key="r4")
    ]], title_color="green")],

    [F.Frame(" PORTS ", [[
        F.Radio("Top 1k", "g2", default=True, key="p1"),
        F.Radio("All", "g2", key="p2"),
        F.Text("Cust:"), F.Input(key="p_c", size=(8,1))
    ]], title_color="green")],

    [F.Frame(" ADVANCED ", [[
        F.Checkbox("NoPing", key="o1"), F.Checkbox("PingOnly", key="o2"),
        F.Text("Script:"), F.Combo(["None", "vuln", "auth", "safe", "banner"], default_value="None", key="k_scr", size=(10,1))
    ]], title_color="orange")],

    [F.Frame(" EVASION ", [[
        F.Text("Decoy:"), F.Input(key="k_dec", size=(10,1)),
        F.Text("Spoof:"), F.Input(key="k_spf", size=(10,1)),
        F.Checkbox("Frag", key="o3"), F.Checkbox("BadSum", key="o4")
    ]], title_color="red")],

    [F.Text("Progress:", text_color="grey"), F.ProgressBar(100, orientation='h', size=(55, 20), key='k_bar', bar_color=('#0f0', '#222'))],
    [F.Multiline(size=(70, 10), key="k_out", text_color="#0f0", background_color="#000", autoscroll=True)],
    [F.Button("INITIATE", size=(60, 1), button_color=("black", "#0f0"))]
]

# Random variable name for window
bucket = F.Window("KAMUI", layout)

# Event Loop
while True:
    e, v = bucket.read()
    
    if e == F.WIN_CLOSED:
        break
        
    # Dummy check
    if junk.scramble() > 200:
        print("This never happens")

    if e == "INITIATE":
        bucket["k_out"].update("")
        bucket["k_bar"].update(0)
        
        # Check target
        t_val = v["k_tgt"]
        if not t_val:
            bucket["k_out"].print("(!) ERROR: NO TARGET")
            continue
            
        # --- COMMAND BUILDER ---
        # we use a temp box
        box = []
        box.append("nmap")
        
        # Logic 
        if v["r1"]: box.append("-sS")
        elif v["r2"]: box.append("-sT")
        elif v["r3"]: box.append("-sU")
        elif v["r4"]: box.append("-A")
        
        # Ports
        if v["p2"]: box.append("-p-")
        if v["p_c"]: 
            box.append("-p")
            box.append(v["p_c"])
            
        # Options
        if v["o1"]: box.append("-Pn")
        if v["o2"]: box.append("-sn")
        
        # Evasion
        if v["k_dec"]:
            box.append("-D")
            box.append(v["k_dec"])
            box.append("-T1")
        else:
            box.append("-T4")
            
        if v["k_spf"]:
            box.append("-S")
            box.append(v["k_spf"])
            box.append("-e")
            box.append("eth0")
            
        if v["o3"]: box.append("-f")
        if v["o4"]: box.append("--badsum")
        
        # Scripts
        s_val = v["k_scr"]
        if s_val != "None":
            txt = "--script=" + s_val
            box.append(txt)
            
        # Stats force
        box.append("--stats-every")
        box.append("1s")
        box.append(t_val)
        
        # Print cmd
        final_str = " ".join(box)
        bucket["k_out"].print(f"RUNNING: {final_str}")
        bucket["k_out"].print("-" * 30)
        
        # --- INLINE THREAD FUNCTION ---
        # Defining function 
        def worker_bee(cmd_list):
            try:
                # Raw popen
                proc = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                for line in proc.stdout:
                    # Dirty string matching
                    if "About" in line:
                        if "%" in line:
                            try:
                                # Split split split
                                temp = line.split("About ")[1]
                                num = temp.split("%")[0]
                                bucket["k_bar"].update(float(num))
                            except:
                                pass
                    
                    bucket["k_out"].print(line.strip())
                    
                bucket["k_bar"].update(100)
                bucket["k_out"].print("\n[+] DONE")
                
            except Exception as err:
                bucket["k_out"].print(f"Error: {err}")
                
        # Start thread
        th = threading.Thread(target=worker_bee, args=(box,), daemon=True)
        th.start()

bucket.close()