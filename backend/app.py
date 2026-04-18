from pathlib import Path
from tempfile import NamedTemporaryFile
import os
import shutil
import uuid

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from starlette.concurrency import run_in_threadpool

from src.pipeline import process_report

app = FastAPI(title="STIX Bundle Generator")

def cleanup_file(path: str) -> None:
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass

@app.post("/api/convert")
async def convert_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
):
    suffix = Path(file.filename or "upload.bin").suffix or ".bin"

    with NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        temp_input_path = tmp.name
        shutil.copyfileobj(file.file, tmp)

    output_name = f"stix_bundle_{uuid.uuid4().hex}.json"

    try:
        output_path = await run_in_threadpool(process_report, temp_input_path, output_name)
    except Exception as e:
        cleanup_file(temp_input_path)
        raise HTTPException(status_code=500, detail=str(e))

    background_tasks.add_task(cleanup_file, temp_input_path)
    background_tasks.add_task(cleanup_file, output_path)

    return FileResponse(
        path = output_path,
        filename = "stix_bundle.json",
        media_type = "application/json",
    )