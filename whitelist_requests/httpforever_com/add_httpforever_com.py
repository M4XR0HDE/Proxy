import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from whitelist_manager import add_to_whitelist
add_to_whitelist('httpforever.com')
