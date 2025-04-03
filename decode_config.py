#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Configuration Processing Tool

This script is used to process configuration data in GitHub Actions.
It will attempt to parse the configuration as JSON and generate a valid configuration file.
"""

import base64
import json
import os
import sys


def decode_config():
    """
    Process configuration data
    
    Get configuration data from the OFFICIAL_CONFIG environment variable,
    try to parse it as JSON, and generate a valid configuration file.
    """
    # Get configuration
    config_data = os.environ.get('OFFICIAL_CONFIG', '')

    # Process configuration
    try:
        if not config_data:
            # Empty configuration, use empty JSON object
            config_json = '{}'
            print("WARNING: No configuration data provided, using empty configuration.")
        else:
            # First try to parse directly as JSON
            try:
                json.loads(config_data)  # Validate JSON
                config_json = config_data
                print("SUCCESS: Configuration processed as JSON.")
            except json.JSONDecodeError:
                # If JSON parsing fails, try to decode as base64
                try:
                    # Fix base64 padding
                    padding = len(config_data) % 4
                    if padding:
                        config_data += '=' * (4 - padding)
                    
                    # Decode
                    config_json = base64.b64decode(config_data).decode('utf-8')
                    
                    # Validate JSON
                    json.loads(config_json)
                    print("SUCCESS: Configuration decoded and processed.")
                except Exception as e:
                    print(f"WARNING: The provided data is not a valid JSON format. Using empty configuration.")
                    print(f"Original error: {str(e)}")
                    config_json = '{}'
        
        # Write configuration file
        with open('official_config.json', 'w') as f:
            f.write(config_json)
        
        # Validate result
        with open('official_config.json', 'r') as f:
            content = json.load(f)
        
        if content:
            print('Configuration validation successful')
            # Output configuration fields but hide sensitive values
            safe_content = {k: '***' if k in ['IMAP_PASS'] else v for k, v in content.items()}
            print(f"Configuration content: {json.dumps(safe_content, ensure_ascii=False)}")
        else:
            print('Configuration is empty')
        
    except Exception as e:
        print(f'Error processing configuration: {str(e)}')
        # Ensure at least one valid configuration file
        with open('official_config.json', 'w') as f:
            f.write('{}')


if __name__ == "__main__":
    decode_config() 