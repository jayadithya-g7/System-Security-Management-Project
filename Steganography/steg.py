import streamlit as st
import numpy as np
from PIL import Image
import io

def text_to_binary(text):
    """Convert text to binary string"""
    binary = ''.join(format(ord(char), '08b') for char in text)
    return binary + '1111111111111110'  # Add delimiter

def encode_image(image, text, num_lsb=1):
    """Encode text into image using LSB steganography"""
    # Convert image to numpy array
    img_array = np.array(image)
    
    # Convert text to binary
    binary_text = text_to_binary(text)
    
    # Calculate maximum bytes that can be encoded
    max_bytes = img_array.size * num_lsb // 8
    
    if len(binary_text) > max_bytes:
        st.error(f"Text too large! Maximum {max_bytes // 8} characters can be encoded.")
        return None
    
    # Flatten the image
    img_flat = img_array.flatten()
    
    # Encode the message
    data_index = 0
    for i in range(len(binary_text)):
        if data_index >= len(img_flat):
            break
            
        # Get the binary value of the pixel
        pixel_value = img_flat[data_index]
        
        # Replace the least significant bit
        if binary_text[i] == '1':
            img_flat[data_index] = pixel_value | 1  # Set LSB to 1
        else:
            img_flat[data_index] = pixel_value & ~1  # Set LSB to 0
            
        data_index += 1
    
    # Reshape the array back to original dimensions
    img_encoded = img_flat.reshape(img_array.shape)
    
    return Image.fromarray(img_encoded)

def decode_image(image, num_lsb=1):
    """Decode text from image"""
    # Convert image to numpy array
    img_array = np.array(image)
    
    # Flatten the image
    img_flat = img_array.flatten()
    
    # Extract binary message
    binary_message = ''
    for i in range(len(img_flat)):
        binary_message += str(img_flat[i] & 1)  # Extract LSB
        
        # Check for delimiter
        if len(binary_message) >= 16 and binary_message[-16:] == '1111111111111110':
            binary_message = binary_message[:-16]
            break
    
    # Convert binary to text
    text = ''
    for i in range(0, len(binary_message), 8):
        if i + 8 <= len(binary_message):
            byte = binary_message[i:i+8]
            text += chr(int(byte, 2))
    
    return text

# Streamlit UI
st.title("Image Steganography")
st.write("Hide text messages within images using LSB steganography")

tab1, tab2 = st.tabs(["Encode", "Decode"])

with tab1:
    st.header("Encode Text into Image")
    
    # Upload image
    uploaded_file = st.file_uploader("Choose an image file (PNG recommended)", type=["png", "jpg", "jpeg"], key="encode_image")
    
    # Text input
    secret_text = st.text_area("Enter the secret message to hide:", key="secret_text")
    
    if uploaded_file is not None:
        original_image = Image.open(uploaded_file)
        st.image(original_image, caption="Original Image", use_column_width=True)
        
        if st.button("Encode Message", key="encode_button"):
            if secret_text:
                with st.spinner("Encoding message..."):
                    encoded_image = encode_image(original_image, secret_text)
                    
                    if encoded_image:
                        st.success("Message encoded successfully!")
                        st.image(encoded_image, caption="Image with Hidden Message", use_column_width=True)
                        
                        # Create download button
                        buf = io.BytesIO()
                        encoded_image.save(buf, format="PNG")
                        byte_im = buf.getvalue()
                        st.download_button(
                            label="Download Encoded Image",
                            data=byte_im,
                            file_name="encoded_image.png",
                            mime="image/png"
                        )
            else:
                st.error("Please enter a message to hide")

with tab2:
    st.header("Decode Text from Image")
    
    # Upload image to decode
    decode_file = st.file_uploader("Choose an image with hidden message", type=["png", "jpg", "jpeg"], key="decode_image")
    
    if decode_file is not None:
        stego_image = Image.open(decode_file)
        st.image(stego_image, caption="Image with Hidden Message", use_column_width=True)
        
        if st.button("Decode Message", key="decode_button"):
            with st.spinner("Decoding message..."):
                decoded_text = decode_image(stego_image)
                
                if decoded_text:
                    st.success("Message decoded successfully!")
                    st.text_area("Decoded Message:", value=decoded_text, height=150, disabled=True)
                else:
                    st.error("No hidden message found or error in decoding")
