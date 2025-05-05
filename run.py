#!/usr/bin/env python3

import os
import sys

# Add the project directory to the Python path
script_dir = os.path.dirname(os.path.abspath(__file__))

from src.main import main

sys.path.insert(0, script_dir)
if __name__ == "__main__":
    main()
