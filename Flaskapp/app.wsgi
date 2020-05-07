#! /usr/bin/python3.7.3

import logging
import sys
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0, '/var/www/Analyzer/Flaskapp/')
from app import app as application
application.secret_key = 'analyzer'
