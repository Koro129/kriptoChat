from flask import Flask
from routes import bp

app = Flask(__name__)

# Registrasi blueprint
app.register_blueprint(bp)

if __name__ == '__main__':
    app.run()
