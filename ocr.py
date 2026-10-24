"""JobShield OCR and Document Parser: Extract text from PDF and image offer letters."""
import base64
import io
import os

try:
    from PIL import Image
except ImportError:
    Image = None

try:
    import pypdf
except ImportError:
    pypdf = None

try:
    import pytesseract
except ImportError:
    pytesseract = None


def extract_from_pdf(file_bytes: bytes) -> tuple[str, str | None]:
    """Extract plain text from a digital PDF offer letter."""
    if not pypdf:
        return "", "pypdf library is not installed."
    try:
        reader = pypdf.PdfReader(io.BytesIO(file_bytes))
        extracted = []
        for i, page in enumerate(reader.pages):
            txt = page.extract_text()
            if txt:
                extracted.append(txt)
        full_text = "\n\n".join(extracted).strip()
        if not full_text:
            return "", "PDF appears to be a scanned image with no embedded text."
        return full_text, None
    except Exception as e:
        return "", f"Failed to parse PDF: {str(e)}"


def extract_from_image_tesseract(file_bytes: bytes) -> tuple[str, str | None]:
    """Attempt OCR using local Tesseract engine."""
    if not pytesseract or not Image:
        return "", "pytesseract or Pillow not installed."
    try:
        img = Image.open(io.BytesIO(file_bytes))
        text = pytesseract.image_to_string(img)
        if text.strip():
            return text.strip(), None
        return "", "No readable text detected by Tesseract."
    except Exception as e:
        return "", f"Local OCR error: {str(e)}"


def extract_from_image_ai(file_bytes: bytes, mime_type: str, api_key: str) -> tuple[str, str | None]:
    """Extract text from image using OpenRouter multimodal vision model."""
    if not api_key:
        return "", "OpenRouter API Key not provided for Vision OCR."
    
    import requests

    b64_data = base64.b64encode(file_bytes).decode("utf-8")
    vision_models = [
        "google/gemini-2.0-flash-exp:free",
        "meta-llama/llama-3.2-11b-vision-instruct:free",
        "google/gemini-flash-1.5-8b:free",
    ]

    prompt = (
        "Extract all plain text verbatim from this document/image. "
        "Do not summarize, do not add explanations. Output only the exact text present in the image."
    )

    headers = {
        "Authorization": f"Bearer {api_key.strip()}",
        "HTTP-Referer": "https://jobshield.local",
        "X-Title": "JobShield Forensics OCR",
        "Content-Type": "application/json",
    }

    for model in vision_models:
        payload = {
            "model": model,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:{mime_type};base64,{b64_data}"
                            },
                        },
                    ],
                }
            ],
            "max_tokens": 1500,
        }
        try:
            r = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers=headers,
                json=payload,
                timeout=25,
            )
            if r.status_code == 200:
                data = r.json()
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                if content.strip():
                    return content.strip(), None
        except Exception:
            continue

    return "", "Vision AI models were unable to transcribe the image."


def extract_from_image_gemini(file_bytes: bytes, mime_type: str, api_key: str) -> tuple[str, str | None]:
    """Extract text from image using Google Gemini Vision API."""
    import requests
    if not api_key:
        return "", "Google Gemini API key not provided."
    b64_data = base64.b64encode(file_bytes).decode("utf-8")
    for g_model in ["gemini-2.0-flash", "gemini-1.5-flash"]:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{g_model}:generateContent?key={api_key.strip()}"
        body = {
            "contents": [
                {
                    "parts": [
                        {"text": "Extract all plain text verbatim from this document/image. Do not summarize, output only the exact text present in the image."},
                        {
                            "inlineData": {
                                "mimeType": mime_type,
                                "data": b64_data
                            }
                        }
                    ]
                }
            ]
        }
        try:
            r = requests.post(url, json=body, timeout=25, headers={"Content-Type": "application/json"})
            if r.status_code == 200:
                data = r.json()
                text = data["candidates"][0]["content"]["parts"][0]["text"]
                if text.strip():
                    return text.strip(), None
        except Exception:
            continue
    return "", "Google Gemini Vision was unable to transcribe the image."


def extract_text(uploaded_file, api_key: str = "") -> tuple[str, str | None]:
    """Unified file text extractor handling PDFs and images."""
    if not uploaded_file:
        return "", "No file uploaded."

    filename = uploaded_file.name.lower()
    file_bytes = uploaded_file.getvalue()

    if filename.endswith(".pdf"):
        text, err = extract_from_pdf(file_bytes)
        if text:
            return text, None
        return "", err or "Unable to extract text from PDF."

    # Image formats (.png, .jpg, .jpeg, .webp)
    mime = "image/png"
    if filename.endswith(".jpg") or filename.endswith(".jpeg"):
        mime = "image/jpeg"
    elif filename.endswith(".webp"):
        mime = "image/webp"

    # Try local Tesseract first (e.g. on Streamlit Cloud with packages.txt)
    text, err = extract_from_image_tesseract(file_bytes)
    if text:
        return text, None

    # Fallback to Gemini if key starts with AIza
    if api_key:
        clean_key = api_key.strip()
        if clean_key.startswith("AIza"):
            text, gemini_err = extract_from_image_gemini(file_bytes, mime, clean_key)
            if text:
                return text, None
            return "", f"{err} | Gemini Vision: {gemini_err}"

        # Otherwise try OpenRouter Vision, and if that fails, try Gemini as well
        text, ai_err = extract_from_image_ai(file_bytes, mime, clean_key)
        if text:
            return text, None
        text, gemini_err = extract_from_image_gemini(file_bytes, mime, clean_key)
        if text:
            return text, None
        return "", f"{err} | AI Vision: {ai_err}"

    return "", (
        "Could not read image. Local Tesseract is not installed on this machine, "
        "and no API key was provided for Vision AI extraction."
    )
