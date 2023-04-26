from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    firstname = db.Column(db.String(20), nullable=False)
    lastname = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_active = db.Column(db.Boolean(), unique=False, nullable=False, default=True)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)
    role = db.relationship("Roles", backref="users")

    def __repr__(self):
        return f'<{self.username}>'

    def __init__(self, username, firstname, lastname, email, password, role_id):
        self.username = username
        self.firstname = firstname
        self.lastname = lastname
        self.email = email
        self.password = password
        self.role_id = role_id

    def serialize(self):
        return {
            "id": self.id,
            "username": self.username,
            "firstname": self.firstname, 
            "lastname": self.lastname, 
            "email": self.email,
            "role": self.role.serialize()
        }

class Roles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(80), unique=True, nullable=False)

    def __repr__(self):
        return f'<{self.type}>'

    def __init__(self, type):
        self.type = type

    def serialize(self):
        return {
            "id": self.id,
            "type": self.type
        }  
