# Static Assets for Subscription App

This directory holds static files served directly by the web server (or Flask in development mode) for the subscription application frontend.

## Files

*   **`background.jpg`**: This is the background image used by the `index.html` template.
    *   **Action Required:** Replace the placeholder `background.jpg` (if one exists) or place your desired background image file here and ensure it is named `background.jpg`. The deployment script does **not** automatically provide a background image.
*   **(Other static files):** You can place other static assets like CSS files (if not embedded in HTML), JavaScript files (if not embedded), fonts, or other images here. They can be referenced in `index.html` using relative paths starting from `/static/` (e.g., `<link rel="stylesheet" href="/static/style.css">`).

## Deployment

Files in this directory are served automatically by Flask (when configured correctly, usually default) or should be configured to be served by the production web server (like Nginx/Apache if used as a frontend, although in our current setup HAProxy forwards directly to Gunicorn/Flask). Ensure the `subapp` user (or whichever user runs the Flask application) has read permissions for these files.
