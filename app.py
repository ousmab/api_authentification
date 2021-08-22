import sqlalchemy
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from uuid import uuid4
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import  wraps


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers["x-access-token"]

        if not token:
            return jsonify({"message":"missing token !"})

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'],algorithms="HS256")
            current_user = Users.query.filter_by(public_id=data['public_id']).first()

        except:
            jsonify({"message":"token is invalid !"})
        return f(current_user, *args, **kwargs)
    return decorated

app = Flask(__name__)

app.config["SECRET_KEY"] = "amide4919bddjwwd"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data.db"

db = SQLAlchemy(app)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.Integer, unique=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(255))
    admin = db.Column(db.Boolean, default=False)


@app.before_first_request
def before_request():
    db.create_all()


@app.route('/users/create', methods=['POST'])
@token_required
def create_user(current_user):
    print(current_user)
    data = request.get_json(force=True)
    password_crypt = generate_password_hash(data['password'].strip())
    try:
        new_user = Users(username=data['username'], public_id=str(uuid4()), password=password_crypt)
        db.session.add(new_user)
        db.session.commit()
    except:
        return jsonify({"message": "and error occurred !"})
    return jsonify({"message": "user created successful !"})



@app.route('/users/<public_id>', methods=['GET'])
def get_user(public_id):
    user = Users.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message": "user not found !"})

    user_as_json = {'username': user.username, 'public_id': user.public_id, 'admin': user.admin,
                    'password': user.password}
    return jsonify(user_as_json)


@app.route("/login", methods=['GET'])
def login():
    """
    comment on gere la redirection si la connexion a reussi ?
    :return:
    """
    auth = request.authorization
    if not auth and not auth.username and not auth.password:
        return make_response('Could not verify !', 401, {"WWW-Authenticate": "realm= 'Login required '"})

    user = Users.query.filter_by(username=auth.username).first()
    if not user:
        return make_response('Could not verify !', 401, {"WWW-Authenticate": "realm= 'Login required '"})

    if check_password_hash(user.password, auth.password):
        # generer le token et l'envoyer
        token = jwt.encode({'public_id': user.public_id,
                            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}
                           , app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({"token": token})

    return make_response('Could not verify !', 401, {"WWW-Authenticate": "realm= 'Login required '"})


if __name__ == "__main__":
    app.run(debug=True)
