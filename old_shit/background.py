import math
import random
from PIL import Image, ImageDraw, ImageFilter

def hex_to_rgb(hex_color):
    """Converts hex color string (#RRGGBB) to an (R, G, B) tuple."""
    hex_color = hex_color.lstrip('#')
    return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

def create_material_background(
    width=1920,
    height=1080,
    filename="background.jpg",
    # --- Configurable Parameters ---
    gradient_start_color_hex="#0a0f2c",
    gradient_end_color_hex="#1e1a31",
    blob_colors_hex=[ "#4a00e0", "#8e2de2", "#300a6e", "#0f2027", ],
    num_blobs=4,
    blob_min_scale=0.4,
    blob_max_scale=0.9,
    blob_alpha=70,
    blob_blur_radius=120,
    noise_intensity=0.05
    # --- End Parameters ---
):
    print(f"Generating '{filename}' ({width}x{height})...")

    # --- 1. Base Diagonal Gradient ---
    print("Step 1: Creating base gradient...")
    base_img = Image.new("RGB", (width, height))
    draw = ImageDraw.Draw(base_img)
    start_rgb = hex_to_rgb(gradient_start_color_hex)
    end_rgb = hex_to_rgb(gradient_end_color_hex)
    for y in range(height):
        for x in range(width):
            norm_pos = max(0.0, min(1.0, (x + (height - 1 - y)) / (width + height - 2)))
            r = int(start_rgb[0] + (end_rgb[0] - start_rgb[0]) * norm_pos)
            g = int(start_rgb[1] + (end_rgb[1] - start_rgb[1]) * norm_pos)
            b = int(start_rgb[2] + (end_rgb[2] - start_rgb[2]) * norm_pos)
            draw.point((x, y), fill=(r, g, b))

    # --- 2. Soft Blurred Blobs ---
    print("Step 2: Creating soft blob layer...")
    blob_layer = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    blob_draw = ImageDraw.Draw(blob_layer)
    img_diagonal = math.sqrt(width**2 + height**2)
    blob_rgbas = [(r, g, b, blob_alpha) for r, g, b in [hex_to_rgb(c) for c in blob_colors_hex]]
    for i in range(num_blobs):
        blob_color = random.choice(blob_rgbas)
        radius_x = random.uniform(blob_min_scale, blob_max_scale) * img_diagonal / 2
        radius_y = random.uniform(blob_min_scale, blob_max_scale) * img_diagonal / 2
        center_x = random.uniform(-radius_x * 0.2, width + radius_x * 0.2)
        center_y = random.uniform(-radius_y * 0.2, height + radius_y * 0.2)
        box = [center_x - radius_x, center_y - radius_y, center_x + radius_x, center_y + radius_y]
        blob_draw.ellipse(box, fill=blob_color)
        print(f"  - Drawn blob {i+1} with color {blob_color[:3]} at ({int(center_x)}, {int(center_y)})")

    # --- 3. Blur Blobs ---
    if blob_blur_radius > 0:
        print(f"Step 3: Blurring blob layer (radius={blob_blur_radius})...")
        blob_layer = blob_layer.filter(ImageFilter.GaussianBlur(blob_blur_radius))

    # --- 4. Composite Blobs onto Base ---
    print("Step 4: Compositing blobs onto base...")
    composite_img = Image.alpha_composite(base_img.convert("RGBA"), blob_layer)
    composite_img = composite_img.convert("RGB")

    # --- 5. Add Subtle Noise (FIXED) ---
    if noise_intensity > 0:
        print(f"Step 5: Adding noise (intensity={noise_intensity:.2f})...")
        noise_img = Image.new("RGB", (width, height))
        # Create a list of pixel tuples instead of a flat bytearray
        noise_pixel_data = []
        for _ in range(width * height):
            # Generate random noise value centered around 128
            noise_val = random.randint(128 - 30, 128 + 30) # Adjust range for noise contrast
            # Append the (R, G, B) tuple for this pixel
            noise_pixel_data.append((noise_val, noise_val, noise_val))

        # Put the sequence of tuples into the image
        noise_img.putdata(noise_pixel_data)

        # Blend the noise layer softly onto the main image
        final_img = Image.blend(composite_img, noise_img, alpha=noise_intensity)
    else:
        final_img = composite_img # No noise requested

    # --- 6. Save Image ---
    print(f"Step 6: Saving image to '{filename}'...")
    try:
        final_img.save(filename, "JPEG", quality=92, optimize=True)
        print(f"Successfully created '{filename}'")
    except Exception as e:
        print(f"Error saving image '{filename}': {e}")

# --- Main Execution ---
if __name__ == "__main__":
    create_material_background()
