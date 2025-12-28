"""
Configuration management for the SSH Brute Force Analyzer.

Loads settings from config.json when present; otherwise writes and uses
well-chosen defaults. Exposes dict-like access and a helper for converting
the active configuration to a plain dict.
"""
import json
import os
from typing import Dict, Any


class Config:
    """
    Load and manage analyzer configuration.

    Keys:
    - max_attempts: threshold for short-window brute-force detection
    - time_window_minutes: size of detection window in minutes
    - summary_limit: max rows to display in the summary table
    - verbose_limit: max IPs to include in verbose mode
    - block_threshold: persistent attempts threshold to recommend blocking
    - monitor_threshold: persistent attempts threshold to recommend monitoring
    - color_enabled: enable ANSI colors in terminal output
    """
    
    # Default configuration
    DEFAULTS = {
        "max_attempts": 5,
        "time_window_minutes": 10,
        "summary_limit": 20,
        "verbose_limit": 10,
        "block_threshold": 50,
        "monitor_threshold": 20,
        "color_enabled": True
    }
    
    def __init__(self, config_path: str = "config.json"):
        """
        Initialize config from file or defaults.
        
        Args:
            config_path: Path to config.json file
        """
        self.config = self.DEFAULTS.copy()
        self.config_path = config_path
        self.loaded_from_file = False
        
        if os.path.exists(config_path):
            self._load_from_file(config_path)
        else:
            self._create_default_config(config_path)
    
    def _load_from_file(self, config_path: str):
        """Load configuration values from a JSON file at `config_path`."""
        try:
            with open(config_path, 'r') as f:
                file_config = json.load(f)
            
            # Merge with defaults (file overrides defaults)
            self.config.update(file_config)
            self.loaded_from_file = True
            print(f"✓ Loaded config from {config_path}")
        except json.JSONDecodeError as e:
            print(f"⚠ Error reading {config_path}: {e}")
            print(f"  Using default configuration")
        except Exception as e:
            print(f"⚠ Error loading config: {e}")
            print(f"  Using default configuration")
    
    def _create_default_config(self, config_path: str):
        """Write DEFAULTS to `config_path` to bootstrap configuration."""
        try:
            with open(config_path, 'w') as f:
                json.dump(self.DEFAULTS, f, indent=2)
            print(f"✓ Created default config at {config_path}")
        except Exception as e:
            print(f"⚠ Could not create config file: {e}")
    
    def get(self, key: str, default=None) -> Any:
        """Return the value for `key`, or `default` if the key is missing."""
        return self.config.get(key, default)
    
    def __getitem__(self, key: str) -> Any:
        """Dict-style access to configuration values (e.g., config["summary_limit"])."""
        return self.config[key]
    
    def __str__(self) -> str:
        """Return a human-readable representation of the active configuration."""
        lines = ["Current Configuration:"]
        for key, value in self.config.items():
            lines.append(f"  {key}: {value}")
        return "\n".join(lines)
    
    def to_dict(self) -> Dict[str, Any]:
        """Return a shallow copy of the active configuration as a dict."""
        return self.config.copy()
