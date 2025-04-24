from database import db
from flask_login import UserMixin 

class User(db.Model, UserMixin):
    # id (inteiro), username (text), password (text)
    id = db.Column(db.Integer, primary_key=True) #Chave que identifica registro na tabéla - Chave Única - Por meio dela que realiza consulta
    username = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

