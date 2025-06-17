import os
import pickle
import pandas as pd
import tempfile
import base64
from encryption_algorithms.ascon_image import ascon_encrypt, ascon_decrypt
from encryption_algorithms.present import present_encrypt, present_decrypt
from encryption_algorithms.hummingbird2 import hummingbird2_encrypt, hummingbird2_decrypt
from encryption_algorithms.speck import speck_encrypt, speck_decrypt
from encryption_algorithms.simon import simon_encrypt, simon_decrypt
from encryption_algorithms.clefia import clefia_encrypt, clefia_decrypt
import csv
import gradio as gr
import shutil
import time

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Load model with error handling
try:
    with open("model.pkl", "rb") as f:
        model, label_encoder = pickle.load(f)  # Unpack the tuple
    print("Model and label encoder loaded successfully.")
except Exception as e:
    print(f"Error loading model.pkl: {str(e)}")
    raise

# Encode local image as base64
try:
    with open("photo.png", "rb") as photo_file:
        photo_base64 = base64.b64encode(photo_file.read()).decode('utf-8')
        INTRO_PHOTO_URL = f"data:image/png;base64,{photo_base64}"
except FileNotFoundError:
    print("Error: photo.png not found in the current directory.")
    INTRO_PHOTO_URL = "https://via.placeholder.com/200?text=Intro+Photo"

# Custom CSS for professional styling
custom_css = """
body {
    font-family: 'Inter', sans-serif;
    background-color: #F3F4F6;
    color: #1F2937;
}
.header-gradient {
    background: linear-gradient(90deg, #1E3A8A 0%, #3B82F6 100%);
    padding: 1rem 1.5rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    color: white;
    border-radius: 8px 8px 0 0;
}
.header-gradient h1 {
    font-size: 1.5rem;
    font-weight: 700;
}
.header-gradient a {
    color: white;
    margin: 0 1rem;
    text-decoration: none;
}
.header-gradient a:hover {
    text-decoration: underline;
}
.card {
    background-color: #FFFFFF;
    border-radius: 8px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    padding: 1.5rem;
    margin-bottom: 1.5rem;
}
button {
    background-color: #3B82F6;
    color: white;
    padding: 0.75rem 1.5rem;
    border-radius: 0.5rem;
    font-weight: 600;
    transition: background-color 0.3s ease, transform 0.2s ease;
}
button:hover {
    background-color: #2563EB;
    transform: scale(1.05);
}
#intro-section {
    text-align: center;
    padding: 3rem 2rem;
    max-width: 900px;
    margin: 0 auto;
}
#intro-section img {
    margin: 0 auto 2.5rem;
    max-width: 250px;
    height: auto;
    border-radius: 50%;
    border: 4px solid white;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}
#intro-section .intro-content {
    background-color: #FFFFFF;
    border-radius: 8px;
    padding: 2rem;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    max-width: 600px;
    margin: 0 auto;
}
#intro-section h1 {
    color: #1E3A8A;
    font-size: 2.5rem;
    font-weight: 700;
    margin-bottom: 0.75rem;
}
#intro-section p.slogan {
    color: #3B82F6;
    font-size: 1.375rem;
    font-weight: 600;
    margin-bottom: 1.5rem;
}
#intro-section p.description {
    color: #1F2937;
    font-size: 1.25rem;
    line-height: 1.75;
    margin-bottom: 2rem;
    text-align: center;
}
h2 {
    color: #1E3A8A;
    font-size: 1.875rem;
    font-weight: 700;
    text-align: center;
    margin-bottom: 1.5rem;
}
.main-content {
    padding: 2rem;
    max-width: 1200px;
    margin: 0 auto;
}
.file-input {
    background-color: #E0E7FF;
    border: 2px dashed #3B82F6;
    border-radius: 0.5rem;
    padding: 1rem;
    text-align: center;
    color: #1F2937;
    font-size: 0.875rem;
    height: 60px;
}
.file-input:hover {
    background-color: #C7D2FE;
}
.download-box {
    padding: 0.5rem;
    font-size: 0.875rem;
    height: 40px;
}
"""

def calculate_entropy(data_bytes):
    from math import log2
    if not data_bytes:
        return 0
    freq = [0] * 256
    for byte in data_bytes:
        freq[byte] += 1
    probs = [f / len(data_bytes) for f in freq if f > 0]
    return -sum(p * log2(p) for p in probs)

def generate_explanation(algorithm, data_type, priority, hardware):
    base_explanations = {
        "ASCON": {
            "security": "ASCON is a NIST Lightweight Cryptography finalist, offering authenticated encryption with a 128-bit key and nonce, ensuring robust protection against attacks. It’s suitable for {hardware} as it balances security and performance, with hardware implementations achieving low latency. ASCON is recommended by NIST for lightweight applications (NIST IR 8454, 2023).",
            "speed": "ASCON provides efficient encryption with a focus on security, suitable for {hardware} when speed is a secondary concern, leveraging its low-latency design.",
            "memory": "ASCON’s implementation is optimized for memory-constrained devices like {hardware}, offering a good balance of security and memory usage."
        },
        "Hummingbird-2": {
            "security": "Hummingbird-2 is an ultra-lightweight cipher with a 256-bit key, designed for constrained devices like {hardware}, requiring less than 2 KB of memory. It provides adequate security for small data sizes, though less suited for large {data_type} due to its 16-bit block size. It’s recognized in academic research for minimal resource requirements (e.g., IEEE Transactions on Computers, 2011).",
            "speed": "Hummingbird-2 offers lightweight encryption with minimal overhead, suitable for {hardware} when speed is prioritized, though less efficient for larger {data_type}.",
            "memory": "Hummingbird-2 is ideal for {hardware}’s limited memory, requiring less than 2 KB, making it a top choice for memory-constrained encryption of {data_type}."
        },
        "Speck": {
            "security": "Speck is a lightweight block cipher with a 64-bit block size and 128-bit key, designed by the NSA for {hardware}. It provides decent security with low computational overhead.",
            "speed": "Speck is optimized for performance on {hardware}, achieving high throughput (e.g., 1 Gbps on modern microcontrollers) due to its low computational overhead.",
            "memory": "Speck requires minimal memory (less than 1 KB for implementation), making it ideal for {hardware}’s constraints."
        },
        "PRESENT": {
            "security": "PRESENT is a lightweight block cipher with 80/128-bit key options, standardized by ISO/IEC 29192-2:2012, offering strong security for {hardware}.",
            "speed": "PRESENT is optimized for high-speed encryption on {hardware}, achieving low latency on structured data.",
            "memory": "PRESENT requires a small memory footprint (around 1 KB), ideal for {hardware}’s memory constraints."
        },
        "CLEFIA": {
            "security": "CLEFIA is a 128-bit block cipher with a 128-bit key, standardized by ISO/IEC 29192-2:2012, providing strong resistance against differential and linear cryptanalysis for {hardware}.",
            "speed": "CLEFIA offers a good balance of security and speed, suitable for {hardware} when performance is a priority.",
            "memory": "CLEFIA’s efficient implementation suits {hardware}’s memory limits while maintaining security."
        },
        "Simon": {
            "security": "Simon is a lightweight block cipher designed by the NSA, offering decent security for {hardware} with a focus on efficiency.",
            "speed": "Simon provides high-speed encryption on {hardware} due to its streamlined design.",
            "memory": "Simon requires minimal memory, making it suitable for {hardware}’s constraints."
        }
    }
    explanation_template = base_explanations.get(algorithm, {}).get(priority.lower(), f"{algorithm} selected for {data_type} with {priority.lower()} priority on {hardware} based on model optimization.")
    return explanation_template.format(hardware=hardware, data_type=data_type)

def process_file(file_obj, hardware, priority):
    print(f"Starting process_file with file_obj: {file_obj}")
    
    if not file_obj:
        return None, "Error: No file object provided."
    temp_path = file_obj.name
    print(f"Temporary file path: {temp_path}")
    
    if not os.path.exists(temp_path):
        return None, f"Error: Temporary file not found at {temp_path}."
    try:
        file_size = os.path.getsize(temp_path)
        print(f"Initial file size check: {file_size} bytes")
    except Exception as e:
        return None, f"Error checking file size: {str(e)}"

    file_content = None
    for attempt in range(3):
        try:
            with open(temp_path, "rb") as source:
                file_content = source.read()
                print(f"Attempt {attempt + 1}: Read {len(file_content)} bytes from source file")
                if len(file_content) > 0:
                    break
            time.sleep(2)
        except PermissionError as pe:
            return None, f"Permission Error reading source file: {str(pe)}"
        except Exception as e:
            return None, f"Error reading source file: {str(e)}"
    
    if file_content is None or len(file_content) == 0:
        return None, f"Error: Source file {temp_path} is empty after multiple attempts."

    filename = os.path.basename(temp_path)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    print(f"Target filepath for copy: {filepath}")

    try:
        with open(filepath, "wb") as destination:
            destination.write(file_content)
            print(f"Wrote {len(file_content)} bytes to {filepath}")
    except PermissionError as pe:
        return None, f"Permission Error copying file: {str(pe)}"
    except Exception as e:
        return None, f"Error copying file: {str(e)}"

    if not os.path.exists(filepath):
        return None, f"Error: Copied file not created at {filepath}."
    file_size = os.path.getsize(filepath)
    if file_size == 0:
        return None, f"Error: Copied file at {filepath} is empty."
    print(f"Copied file size: {file_size} bytes")

    try:
        with open(filepath, "rb") as f:
            file_bytes = f.read()
        print(f"Read {len(file_bytes)} bytes from copied file")
    except Exception as e:
        return None, f"Error reading copied file: {str(e)}"

    if not file_bytes:
        return None, f"Error: File content at {filepath} is empty."

    file_size = os.path.getsize(filepath)
    line_count = len(file_bytes.splitlines())
    entropy = calculate_entropy(file_bytes)
    print(f"File info - Size: {file_size}, Line Count: {line_count}, Entropy: {entropy}")

    extension_txt = 1 if filename.endswith('.txt') else 0
    extension_csv = 1 if filename.endswith('.csv') else 0
    extension_img = 1 if filename.lower().endswith(('.jpg', '.jpeg', '.png', '.bmp')) else 0
    print(f"Extensions - Img: {extension_img}, Txt: {extension_txt}, CSV: {extension_csv}")

    priority_speed = 1 if priority == "Speed" else 0
    priority_security = 1 if priority == "Security" else 0
    priority_memory = 1 if priority == "Memory" else 0
    print(f"Priority - Speed: {priority_speed}, Security: {priority_security}, Memory: {priority_memory}")

    # Map hardware to one-hot encoded columns as expected by the model
    hardware_arduino = 1 if hardware == "Arduino" else 0
    hardware_esp32 = 1 if hardware == "ESP32" else 0
    hardware_rpi = 1 if hardware == "Raspberry Pi" else 0

    # Prepare features DataFrame matching the training features
    features = pd.DataFrame([{
        'File_Size_KB': file_size / 1024,  # Convert bytes to KB
        'Hardware_Arduino Uno': hardware_arduino,
        'Hardware_ESP32': hardware_esp32,
        'Hardware_Raspberry Pi 4': hardware_rpi,
        'File_Type_bin': 0,  # Assuming no binary files in GUI
        'File_Type_jpg': extension_img,
        'File_Type_txt': extension_txt,
        'priority_speed': priority_speed * 20,  # Scale as in training
        'priority_security': priority_security * 20,
        'priority_memory': priority_memory * 20,
        'avg_time_ms': 0.5,  # Placeholder (model doesn't use this directly for prediction)
        'time_memory_ratio': 1.0,  # Placeholder
        'time_memory_interaction': 0.5  # Placeholder
    }])
    print(f"Features: {features.to_dict(orient='records')}")

    try:
        # Predict the encoded label and decode it using the label encoder
        predicted_label = model.predict(features)[0]
        algorithm = label_encoder.inverse_transform([predicted_label])[0]
        print(f"Predicted algorithm: {algorithm}")
    except Exception as e:
        return None, f"Error predicting algorithm: {str(e)}"

    data_type = "Image" if extension_img else "Text" if extension_txt else "CSV" if extension_csv else "Unknown"
    explanation = generate_explanation(algorithm, data_type, priority, hardware)
    hardware_context = {
        "Arduino": "Arduino’s limited processing power and memory make lightweight algorithms essential for efficient encryption.",
        "Raspberry Pi": "Raspberry Pi supports more computational resources, allowing for a balance between security and performance.",
        "ESP32": "ESP32 benefits from algorithms optimized for both speed and low power consumption, suitable for IoT applications."
    }
    hardware_info = hardware_context.get(hardware, "Hardware context not specified.")
    full_explanation = f"{explanation} {hardware_info}"
    print(f"Explanation: {full_explanation}")

    key = b"thisisakey123456"
    nonce = b"thisisanonce1234"
    aad = b""

    try:
        if algorithm == "ASCON":
            encrypted_data = ascon_encrypt(key, nonce, aad, file_bytes)
        elif algorithm == "PRESENT":
            encrypted_data = present_encrypt(file_bytes)
        elif algorithm == "Hummingbird-2":
            encrypted_data = hummingbird2_encrypt(file_bytes)
        elif algorithm == "Speck":
            encrypted_data = speck_encrypt(file_bytes, key)
        elif algorithm == "Simon":
            encrypted_data = simon_encrypt(file_bytes, key)
        elif algorithm == "CLEFIA":
            encrypted_data = clefia_encrypt(file_bytes, key)
        else:
            encrypted_data = file_bytes
        print(f"Encrypted data length: {len(encrypted_data)} bytes")
    except Exception as e:
        return None, f"Error during encryption: {str(e)}"

    if not encrypted_data:
        return None, "Error: Encrypted data is empty."

    encrypted_filename = f"encrypted_{algorithm}_{filename}"
    encrypted_path = os.path.join(UPLOAD_FOLDER, encrypted_filename)
    print(f"Saving encrypted file to: {encrypted_path}")
    try:
        with open(encrypted_path, "wb") as f:
            f.write(encrypted_data)
        print(f"Successfully saved encrypted file at {encrypted_path}")
        time.sleep(0.5)  # Small delay to ensure file is ready
        if not os.path.exists(encrypted_path) or os.path.getsize(encrypted_path) == 0:
            return None, f"Error: Encrypted file not properly saved at {encrypted_path}."
    except Exception as e:
        return None, f"Error saving encrypted file: {str(e)}"

    log_path = os.path.join(UPLOAD_FOLDER, "history_log.csv")
    try:
        with open(log_path, "a", newline="") as csvfile:
            writer = csv.writer(csvfile)
            if not os.path.exists(log_path) or os.path.getsize(log_path) == 0:
                writer.writerow(['Filename', 'Hardware', 'Algorithm', 'Priority', 'Entropy', 'File Size', 'Line Count'])
            writer.writerow([filename, hardware, algorithm, priority, entropy, file_size, line_count])
    except Exception as e:
        return None, f"Error logging history: {str(e)}"

    return {
        "algorithm": algorithm,
        "explanation": full_explanation,
        "encrypted_path": encrypted_path,
        "encrypted_preview": encrypted_data[:100].hex() if len(encrypted_data) > 0 else "No preview available",
        "file_size": file_size,
        "line_count": line_count,
        "entropy": entropy,
        "decrypted_path": None
    }, None

def decrypt_file(encrypted_path):
    print(f"Decrypting file: {encrypted_path}")
    if not os.path.exists(encrypted_path):
        return None, f"Encrypted file not found at {encrypted_path}."

    try:
        with open(encrypted_path, "rb") as f:
            encrypted_data = f.read()
        print(f"Read {len(encrypted_data)} bytes from encrypted file")
    except Exception as e:
        return None, f"Error reading encrypted file: {str(e)}"

    key = b"thisisakey123456"
    nonce = b"thisisanonce1234"
    aad = b""

    filename = os.path.basename(encrypted_path)
    try:
        if "ASCON" in filename.upper():
            decrypted_data = ascon_decrypt(key, nonce, aad, encrypted_data)
        elif "PRESENT" in filename.upper():
            decrypted_data = present_decrypt(encrypted_data)
        elif "HUMMINGBIRD-2" in filename.upper():
            decrypted_data = hummingbird2_decrypt(encrypted_data)
        elif "SPECK" in filename.upper():
            decrypted_data = speck_decrypt(encrypted_data, key)
        elif "SIMON" in filename.upper():
            decrypted_data = simon_decrypt(encrypted_data, key)
        elif "CLEFIA" in filename.upper():
            decrypted_data = clefia_decrypt(encrypted_data, key)
        else:
            return None, "Algorithm type not found in filename."
        print(f"Decrypted data length: {len(decrypted_data)} bytes")
    except Exception as e:
        return None, f"Error during decryption: {str(e)}"

    if not decrypted_data:
        return None, "Error: Decrypted data is empty."

    decrypted_filename = f"decrypted_{filename}"
    decrypted_path = os.path.join(UPLOAD_FOLDER, decrypted_filename)
    print(f"Saving decrypted file to: {decrypted_path}")
    try:
        with open(decrypted_path, "wb") as f:
            f.write(decrypted_data)
        print(f"Successfully saved decrypted file at {decrypted_path}")
        time.sleep(0.5)  # Small delay to ensure file is ready
        if not os.path.exists(decrypted_path) or os.path.getsize(decrypted_path) == 0:
            return None, f"Error: Decrypted file not properly saved at {decrypted_path}."
    except Exception as e:
        return None, f"Error saving decrypted file: {str(e)}"

    return decrypted_path, None

def gradio_interface(hardware, file, priority):
    print(f"Gradio inputs - Hardware: {hardware}, File: {file}, Priority: {priority}")
    if not file:
        return "Please upload a file.", None, None, None, None, None, "Error: No file uploaded."

    result, error = process_file(file, hardware, priority)
    if error:
        print(f"Process file error: {error}")
        return "Error occurred.", None, None, None, None, None, error

    algorithm = result["algorithm"]
    explanation = result["explanation"]
    encrypted_path = result["encrypted_path"]
    encrypted_preview = result["encrypted_preview"]
    file_size = result["file_size"]
    line_count = result["line_count"]
    entropy = result["entropy"]

    file_info = f"**File Size:** {file_size} bytes\n**Line Count:** {line_count}\n**Entropy:** {entropy:.2f}"
    print(f"File info: {file_info}")

    decrypted_path, error = decrypt_file(encrypted_path)
    if error:
        print(f"Decrypt file error: {error}")
        return (
            f"✅ Recommended Algorithm: {algorithm}",
            explanation,
            file_info,
            encrypted_preview,
            encrypted_path if os.path.exists(encrypted_path) else None,
            None,
            error
        )
    elif decrypted_path:
        print(f"Decrypted file path returned: {decrypted_path}")
        return (
            f"✅ Recommended Algorithm: {algorithm}",
            explanation,
            file_info,
            encrypted_preview,
            encrypted_path if os.path.exists(encrypted_path) else None,
            decrypted_path if os.path.exists(decrypted_path) else None,
            None
        )
    else:
        return (
            f"✅ Recommended Algorithm: {algorithm}",
            explanation,
            file_info,
            encrypted_preview,
            encrypted_path if os.path.exists(encrypted_path) else None,
            None,
            "Decryption failed silently."
        )

# Gradio Blocks with State Management
with gr.Blocks(css=custom_css) as demo:
    # State to track whether to show intro or main
    show_intro = gr.State(value=True)

    # Header (always visible)
    gr.HTML("""
    <div class="header-gradient">
        <h1>EJAlgoCraft</h1>
        <nav>
            <a href="#">Home</a>
            <a href="#">About</a>
            <a href="#">Contact</a>
        </nav>
    </div>
    """)

    # Main Section (hidden initially)
    with gr.Column(visible=False) as main_section:
        gr.Markdown("## EJAlgoCraft")
        gr.Markdown(
            "Upload a file, select your hardware and priority (Speed, Security, Memory), and get an encrypted file using the recommended algorithm.",
            elem_classes=["text-center"]
        )
        with gr.Row():
            # Inputs Column
            with gr.Column(scale=1, min_width=300):
                with gr.Group(elem_classes=["card"]):
                    hardware = gr.Dropdown(
                        choices=["Arduino", "Raspberry Pi", "ESP32"],
                        label="Select Hardware",
                        value="Arduino"
                    )
                    file = gr.File(label="Upload File", elem_classes=["file-input"])
                    priority = gr.Dropdown(
                        choices=["Speed", "Security", "Memory"],
                        label="Select Priority",
                        value="Speed"
                    )
                    submit_btn = gr.Button("Submit")

            # Outputs Column
            with gr.Column(scale=2, min_width=600):
                with gr.Group(elem_classes=["card"]):
                    prediction = gr.Textbox(label="Prediction", lines=1)
                    explanation = gr.Textbox(label="Explanation", lines=3)
                    file_info = gr.Textbox(label="File Info", lines=2)
                    encrypted_preview = gr.Textbox(label="Encrypted Preview (Hex)", lines=2)
                    encrypted_download = gr.DownloadButton(
                        label="Download Encrypted File",
                        value=None,
                        elem_classes=["download-box"]
                    )
                    decrypted_download = gr.DownloadButton(
                        label="Download Decrypted File",
                        value=None,
                        elem_classes=["download-box"]
                    )
                    error = gr.Textbox(label="Error", lines=1)

    # Introduction Section
    with gr.Column(visible=True) as intro_section:
        gr.Markdown(
            f"""
            <div id="intro-section">
                <img src="{INTRO_PHOTO_URL}" alt="Intro Photo">
                <div class="intro-content">
                    <h1>EJAlgoCraft</h1>
                    <p class="slogan">Select Smarter. Run Faster.</p>
                    <p class="description">
                        Welcome to EJAlgoCraft, your intelligent encryption solution for resource-constrained devices. 
                        We leverage machine learning to recommend the best encryption algorithms based on your hardware, 
                        data type, and priority—whether it's speed, security, or memory efficiency. 
                        Designed for professionals and enthusiasts alike, EJAlgoCraft ensures your data is protected efficiently and effectively.
                    </p>
                </div>
                <button>Get Started</button>
            </div>
            """,
            elem_classes=["text-center"]
        )
        gr.Button("Get Started").click(
            fn=lambda: (gr.update(visible=False), gr.update(visible=True)),
            inputs=None,
            outputs=[intro_section, main_section]
        )

    # Bind the submit button to the gradio_interface function
    submit_btn.click(
        fn=gradio_interface,
        inputs=[hardware, file, priority],
        outputs=[
            prediction,
            explanation,
            file_info,
            encrypted_preview,
            encrypted_download,
            decrypted_download,
            error
        ]
    )

if __name__ == '__main__':
    demo.launch(share=False, server_name="127.0.0.1", server_port=7860, show_error=True)
