# Steganography Web Tool  

A Flask-based web application that allows users to securely hide and reveal secret messages in images using LSB (Least Significant Bit) steganography combined with encryption (Fernet).  

---

## Features  
- Encode Messages: Hide any text inside an image (PNG recommended).  
- Password Protection: All messages are encrypted with a password before embedding.  
- Download Stego-Image: Export the modified image with your hidden message.  
- Decode Messages: Reveal hidden text from a stego-image with the correct password.  
- Capacity Check: Calculates how many characters can be hidden in the selected image.  
- JPEG Warning: Alerts users that JPEG is lossy, recommending PNG.  
- User Interface: TailwindCSS-powered responsive interface with tabs for Encode/Decode.  

---

## Tech Stack  
- Backend: Python, Flask  
- Image Processing: OpenCV, NumPy  
- Encryption: cryptography.fernet  
- Frontend: TailwindCSS, HTML, Jinja2 templates  

---

## Installation  

1. Clone this repository  
   ```bash
   git clone https://github.com/your-username/steganography-web-tool.git
   cd steganography-web-tool
