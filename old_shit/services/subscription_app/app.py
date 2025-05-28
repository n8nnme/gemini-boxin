# ======================================================================
# Subscription Flask Application
# Author: AI Assistant (Based on User Requirements)
# Purpose: Serve subscription page and generate client configs.
# Location: /var/www/subscription_app/app.py (when deployed)
# ======================================================================

import os
import json
import logging
from flask import Flask, render_template, Response, request, abort, url_for

# Initialize Flask App
app = Flask(__name__)

# --- Configuration Loading ---
# Load configuration securely from environment variables set by systemd service.
# Use a dictionary to hold config for easier access and checking.
config = {}
required_env_vars = [
    'MAIN_DOMAIN', 'SUBSCRIPTION_DOMAIN', 'SUBSCRIPTION_BASE64_PATH',
    'API_BASE64_PATH_PREFIX', 'VLESS_PORT', 'VLESS_UUID', 'VLESS_PATH',
    'HYSTERIA2_PORT', 'HYSTERIA2_PASSWORD'
]

try:
    for var in required_env_vars:
        value = os.environ.get(var)
        if not value:
            # Log critical error if required variable is missing
            app.logger.critical(f"Missing required environment variable: {var}")
            # In a production app, you might want to raise an exception or exit
            # For now, we'll allow the app to start but routes might fail.
            raise KeyError(f"Environment variable {var} not set.")
        config[var] = value
    app.logger.info("Successfully loaded configuration from environment variables.")
except KeyError:
    # If any required var is missing, log and potentially exit or handle gracefully
    app.logger.error("Application cannot start due to missing configuration. Check systemd service environment variables.")
    # Depending on deployment strategy, might exit here:
    # import sys
    # sys.exit(1)

# Configure logging (especially when run with Gunicorn)
if __name__ != '__main__': # Only configure when run via WSGI server like Gunicorn
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
    app.logger.info("Flask logger configured to use Gunicorn logger.")

# --- Routes ---

# Route for the main subscription page (using the obscured Base64 path)
# Use config dict to get the path dynamically
@app.route(config.get('SUBSCRIPTION_BASE64_PATH', '/error-path-not-configured'), methods=['GET'])
def index():
    """Renders the main subscription HTML page."""
    try:
        # Pass necessary variables to the Jinja2 template
        return render_template('index.html',
                               subscription_domain=config.get('SUBSCRIPTION_DOMAIN'),
                               api_base64_path_prefix=config.get('API_BASE64_PATH_PREFIX'))
    except Exception as e:
        app.logger.error(f"Error rendering index.html: {e}", exc_info=True)
        abort(500) # Internal Server Error

# Route for generating client configuration JSON (using the obscured Base64 prefix)
# Example URL: /<API_BASE64_PATH_PREFIX>/<username>-<TYPE>-CLIENT.json
@app.route(f"{config.get('API_BASE64_PATH_PREFIX', '/error-prefix-not-configured')}/<config_filename>", methods=['GET'])
def generate_config(config_filename):
    """Generates a Sing-Box client JSON configuration based on the request."""
    app.logger.debug(f"Received config request for: {config_filename}")

    try:
        # Basic parsing of the requested filename
        # Format: <username>-<protocol_type>-CLIENT.json
        # Example: myuser-VLESS-CLIENT.json
        if not config_filename.endswith('-CLIENT.json'):
            app.logger.warning(f"Config request rejected: Invalid filename suffix '{config_filename}'")
            abort(400, "Invalid configuration filename format.")

        base_name = config_filename[:-len('-CLIENT.json')]
        parts = base_name.split('-')

        if len(parts) < 2:
            app.logger.warning(f"Config request rejected: Could not parse username/type from '{base_name}'")
            abort(400, "Invalid configuration filename format (missing username or type).")

        # Extract username and protocol type
        username = parts[0]
        protocol_type = parts[1].upper() # Ensure uppercase for comparison (VLESS or TRJ)

        if not username:
            app.logger.warning(f"Config request rejected: Empty username from '{config_filename}'")
            abort(400, "Username cannot be empty.")

        # Validate protocol type (we generate config based on VLESS/Hy2 anyway)
        if protocol_type not in ["VLESS", "TRJ"]: # TRJ maps to Hy2 in this simple setup
             app.logger.warning(f"Config request rejected: Unsupported protocol type '{protocol_type}' from '{config_filename}'")
             abort(400, "Unsupported protocol type specified.")

        # --- Generate Sing-Box Client JSON Structure ---
        # IMPORTANT: This configuration uses the *INITIAL* VLESS_UUID from the environment.
        # The actual user authentication depends on the list of UUIDs managed within the
        # running Sing-Box instance via the `manage_proxy_users.sh` script.
        # This web page does NOT validate if the requested username corresponds to a valid UUID in Sing-Box.
        client_config = {
            "log": {
                "level": "info", # Client log level
                "timestamp": True
            },
            "outbounds": [
                # VLESS Outbound Configuration
                {
                    "type": "vless",
                    "tag": "proxy-vless", # Tag for routing rules
                    "server": config.get('MAIN_DOMAIN'),
                    "server_port": int(config.get('VLESS_PORT')),
                    "uuid": config.get('VLESS_UUID'), # Use the initial UUID as placeholder
                    "tls": {
                        "enabled": True,
                        "server_name": config.get('MAIN_DOMAIN'), # SNI must match server cert
                        "insecure": False # Set to True only if using self-signed certs AND want to skip verification
                    },
                    "transport": {
                        "type": "http", # Must match server inbound transport
                        "path": config.get('VLESS_PATH') # Must match server inbound path
                    }
                },
                # Hysteria2 Outbound Configuration
                {
                    "type": "hysteria2",
                    "tag": "proxy-hysteria2", # Tag for routing rules
                    "server": config.get('MAIN_DOMAIN'),
                    "server_port": int(config.get('HYSTERIA2_PORT')),
                    "password": config.get('HYSTERIA2_PASSWORD'), # Must match server password
                    "tls": {
                        "enabled": True,
                        "server_name": config.get('MAIN_DOMAIN'), # SNI must match server cert
                        "insecure": False, # Set to True only if using self-signed certs AND want to skip verification
                        "alpn": ["h3"] # Common ALPN for Hysteria2
                    }
                },
                # Standard Direct and Block Outbounds
                { "type": "direct", "tag": "direct" },
                { "type": "block", "tag": "block" }
            ],
            "route": {
                # Routing rules for the client
                "rules": [
                    {
                        # Simple example: Use VLESS if VLESS was requested in URL,
                        # otherwise use Hysteria2 (maps TRJ request to Hy2).
                        # More complex rules could be added here (e.g., by domain).
                        "outbound": "proxy-vless" if protocol_type == "VLESS" else "proxy-hysteria2",
                    }
                ],
                # Default outbound if no specific rules match
                "final": "proxy-vless"
            }
        }

        # Convert Python dict to JSON string
        response_data = json.dumps(client_config, indent=2)

        # Return the JSON response
        app.logger.info(f"Successfully generated config for '{username}' type '{protocol_type}'")
        return Response(response_data, mimetype='application/json')

    except ValueError as e:
        # Handle errors converting port numbers (should not happen if env vars are digits)
        app.logger.error(f"Configuration Error: Invalid integer value from environment variable - {e}", exc_info=True)
        abort(500, "Internal server configuration error.")
    except Exception as e:
        # Catch-all for other unexpected errors during generation
        app.logger.error(f"Unexpected error generating config for {config_filename}: {e}", exc_info=True)
        abort(500, "An internal error occurred while generating the configuration.")

# Health check endpoint for monitoring or HAProxy checks
@app.route('/health', methods=['GET'])
def health_check():
    """Basic health check endpoint."""
    return "OK", 200

# --- Error Handling ---
@app.errorhandler(400)
def bad_request(error):
    app.logger.warning(f"Bad Request (400): {error.description}")
    return {"error": "Bad Request", "message": error.description}, 400

@app.errorhandler(404)
def not_found(error):
    # This might be triggered if the Base64 paths don't match exactly
    app.logger.info(f"Not Found (404): {request.path}")
    return {"error": "Not Found", "message": "The requested resource was not found."}, 404

@app.errorhandler(500)
def internal_server_error(error):
    # Log the underlying error if available
    app.logger.error(f"Internal Server Error (500): {error.description if hasattr(error, 'description') else error}", exc_info=True)
    return {"error": "Internal Server Error", "message": "An unexpected error occurred."}, 500


# --- Main Execution Guard ---
# This block is NOT executed when run by Gunicorn via the systemd service.
# It's only for direct execution (e.g., `python app.py` for development).
if __name__ == '__main__':
    print("WARNING: Running Flask development server. NOT suitable for production.")
    print("Use Gunicorn via the systemd service for production deployment.")
    # Set debug=True for development server only
    # Load environment variables from a .env file if it exists (for local dev)
    try:
        from dotenv import load_dotenv
        load_dotenv()
        print("Loaded environment variables from .env file (if present).")
        # Reload config after loading .env
        for var in required_env_vars:
            config[var] = os.environ.get(var)
    except ImportError:
        print("dotenv not installed, skipping .env file load.")
    except Exception as e:
        print(f"Error loading .env file: {e}")

    # Check config again after potential .env load
    missing_vars = [var for var in required_env_vars if not config.get(var)]
    if missing_vars:
        print(f"ERROR: Missing required environment variables for development: {', '.join(missing_vars)}")
    else:
        # Get port from env or default to 5001 for dev to avoid conflict with prod 5000
        dev_port = int(os.environ.get('FLASK_RUN_PORT', 5001))
        print(f"Starting development server on http://127.0.0.1:{dev_port}")
        app.run(host='127.0.0.1', port=dev_port, debug=True)
