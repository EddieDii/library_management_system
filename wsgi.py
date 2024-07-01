import sys
import site

# Add the site-packages of the chosen virtualenv to work with
site.addsitedir('/var/www/library_management/venv/lib/python3.6/site-packages')

# Add the app's directory to the PYTHONPATH
sys.path.insert(0, '/var/www/library_management')

from app import app as application

from app import app

if __name__ == "__main__":
    app.run()