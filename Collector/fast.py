from fastapi import FastAPI
from fastapi.responses import StreamingResponse
import time
import asyncio
import uvicorn

app = FastAPI()
number = 0

async def number_generator():
    global number
    while True:
        yield f"{number}\n"
        number += 1
        await asyncio.sleep(0.5)

@app.get("/stream")
async def stream_numbers():
    return StreamingResponse(number_generator(), media_type="text/plain")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8675)
