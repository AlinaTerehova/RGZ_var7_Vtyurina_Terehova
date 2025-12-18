import os
from dotenv import load_dotenv

from flask import Flask, request, jsonify
from flask_login import LoginManager, login_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from models import db, User, Ticket

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']
    role = data.get('role', 'user')

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify(message="User with this username already exists"), 400

    user = User(
        username=username,
        password=generate_password_hash(password),
        role=role
    )
    db.session.add(user)
    db.session.commit()
    return jsonify(message='User successfully registered')



@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):
        login_user(user)
        return jsonify(message='Login successful')
    return jsonify(message='Invalid username or password'), 401


@app.route('/tickets', methods=['POST'])
@login_required
def create_ticket():
    data = request.json
    ticket = Ticket(
        title=data['title'],
        description=data.get('description', ''),
        user_id=current_user.id
    )
    db.session.add(ticket)
    db.session.commit()
    return jsonify(message='Ticket successfully created')


@app.route('/tickets', methods=['GET'])
@login_required
def get_tickets():
    if current_user.role == 'admin':
        tickets = Ticket.query.all()
        return jsonify([
            {
                'id': t.id,
                'title': t.title,
                'status': t.status,
                'user_id': t.user_id 
            }
            for t in tickets
        ])
    else:
        tickets = Ticket.query.filter_by(user_id=current_user.id).all()
        return jsonify([
            {
                'id': t.id,
                'title': t.title,
                'status': t.status
            }
            for t in tickets
        ])


@app.route('/tickets/<int:ticket_id>', methods=['GET'])
@login_required
def get_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if current_user.role != 'admin' and ticket.user_id != current_user.id:
        return jsonify(message='Access denied'), 403

    response = {
        'id': ticket.id,
        'title': ticket.title,
        'status': ticket.status
    }

    if current_user.role == 'admin':
        response['username'] = ticket.user.username

    return jsonify(response)


@app.route('/tickets/<int:ticket_id>', methods=['PUT'])
@login_required
def update_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if current_user.role != 'admin' and ticket.user_id != current_user.id:
        return jsonify(message='Not enough permissions'), 403

    data = request.json
    ticket.status = data.get('status', ticket.status)
    db.session.commit()
    return jsonify(message='Ticket successfully updated')


@app.route('/tickets/<int:ticket_id>', methods=['DELETE'])
@login_required
def delete_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if current_user.role != 'admin':
        return jsonify(message='Only admin can delete tickets'), 403

    db.session.delete(ticket)
    db.session.commit()
    return jsonify(message='Ticket successfully deleted')


@app.route('/users', methods=['GET'])
@login_required
def get_users():
    if current_user.role != 'admin':
        return jsonify(message='Admin access only'), 403

    users = User.query.all()
    return jsonify([
        {'id': u.id, 'username': u.username, 'role': u.role}
        for u in users
    ])


@app.route('/users/<int:user_id>', methods=['PUT'])
@login_required
def update_user_role(user_id):
    if current_user.role != 'admin':
        return jsonify(message='Not enough permissions'), 403

    user = User.query.get_or_404(user_id)
    user.role = request.json['role']
    db.session.commit()
    return jsonify(message='User role successfully updated')


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=False)
