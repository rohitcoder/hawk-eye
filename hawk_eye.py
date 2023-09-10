import sys
import os

# Add the root directory to sys.path
root_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, root_dir)

from src.hawk_eye import main

if __name__ == '__main__':
    main.main()
