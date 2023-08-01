import websockets
import asyncio
import json
import re

import hashlib
hash_object = hashlib.sha1(b"your_string_here")


session_hash = "8lqd70pxiql"

num = 7

def gen_message(num, session_hash=session_hash):
    SEND_HASH = f'{{"fn_index":{num},"session_hash":"{session_hash}"}}'

    model = "vicuna-13b"
    temperature = 0.7
    topP = 1
    max_length = 512

    prompt = "Then you exit and start over. This time in the lobby you choose room 2, which has a door to room 4, and room 4 has a door that leads to room 6. You find a chest with 50 dollars in room 6, but you do not take any money, you are just learning about the environment." 
    SEND_PROMPT = f'{{"fn_index":{num},"data":[null,"{prompt}"], "event_data":null,"session_hash":"{session_hash}"}}'
    SEND_DATA = f'{{"fn_index":{num+1},"data":[null,"{model}",{temperature},{topP},{max_length}], "event_data":null,"session_hash":"{session_hash}"}}'

    async def hello():
        async with websockets.connect('wss://chat.lmsys.org/queue/join') as websocket:
            send_hash = await websocket.recv()
            print(f"< {send_hash}")
            await websocket.send(f'{SEND_HASH}')
            estimation = await websocket.recv()
            print(f"< {estimation}")
            send_data = await websocket.recv()
            print(f"< {send_data}")
            await websocket.send(f'{SEND_PROMPT}')
            status = await websocket.recv()
            print(f"< {status}")
            status = await websocket.recv()
            print(f"< {status}")

    async def send_prompt():
        async with websockets.connect('wss://chat.lmsys.org/queue/join') as websocket:
            send_hash = await websocket.recv()
            print(f"< {send_hash}")
            await websocket.send(f'{SEND_HASH}')
            estimation = await websocket.recv()
            print(f"< {estimation}")
            send_data = await websocket.recv()
            print(f"< {send_data}")
            await websocket.send(f'{SEND_DATA}')

            status_str = await websocket.recv()
            status = json.loads(status_str)
            while status['msg'] != 'process_completed':
                status_str = await websocket.recv()
                status = json.loads(status_str)

            html_string = status['output']['data'][1][0][1]

            message = re.search(r'<p>(.*?)</p>', html_string).group(1)
            return message

    asyncio.run(hello())
    completion = asyncio.run(send_prompt())
    return completion

for _ in range(3):
    num = 1
    print(gen_message(num, session_hash=session_hash))
