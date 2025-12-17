from src.apps import create_app
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy

app = create_app()
CORS(app)

if __name__ == '__main__':
    app.run(debug=True,port=3000)