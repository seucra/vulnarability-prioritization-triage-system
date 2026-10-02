from PIL import Image
import os

png_file = "usecase_diagram_short.png"
pdf_file = "usecase_diagram_short.pdf"

if os.path.exists(png_file):
    print(f"Converting {png_file} to PDF...")
    
    # Open the image
    image = Image.open(png_file)
    
    # Convert to RGB (PDF format does not support the alpha/transparency channel directly)
    rgb_image = image.convert('RGB')
    
    # Save as PDF
    rgb_image.save(pdf_file, resolution=100.0)
    
    print(f"Success! Your PDF is ready at: {pdf_file}")
else:
    print(f"Error: Could not find {png_file}. Make sure it is in the same directory.")
