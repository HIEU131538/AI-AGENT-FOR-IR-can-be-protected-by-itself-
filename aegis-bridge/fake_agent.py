from fastapi import FastAPI, Request

app = FastAPI()


@app.post("/ingest/alerts")
async def ingest(req: Request):

    body = await req.json()

    print("\n========== FAKE AGENT ==========")
    print("NHẬN:")
    print(body)
    print("================================")

    return {
        "status": "ok",
        "received": len(
            body.get("alerts", [])
        )
    }
