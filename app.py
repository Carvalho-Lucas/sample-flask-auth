import bcrypt
from flask import Flask, request, jsonify
from database import db 
from models.user import User  
from flask_login import LoginManager, login_user, current_user, logout_user, login_required

app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"  # Obrigatório para funcionamento de sessões e autenticação
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin123@127.0.0.1:3306/flask-crud'

login_maneger = LoginManager()  # Cria o gerenciador de login
db.init_app(app)  # Inicializa a conexão do banco com o app
login_maneger.init_app(app)  # Conecta o gerenciador de login com o app

# Define a rota padrão de redirecionamento para login
login_maneger.login_view = 'login'

# Função obrigatória para carregar o usuário logado a partir do ID salvo na sessão
@login_maneger.user_loader
def load_user(user_id):
     return User.query.get(user_id)

@app.route("/login", methods=["POST"])
def login():
    data  = request.json  
    username = data.get("username")
    password = data.get("password")

    if username and password:
        user = User.query.filter_by(username=username).first()  # Busca o usuário no banco

        if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):  
            login_user(user)  # Efetua o login (salva na sessão)
            print(current_user.is_authenticated) 
            return jsonify({"message": "Credencial validada com sucesso!"})

    return jsonify({"ERROR": "Credencial Inválida!"}), 400 

@app.route("/logout", methods=["GET"])
@login_required #Usuário não consegue acessar rota sem autenticar
def logout():
    logout_user()# limpa a sessão e desloga o usuário
    return jsonify({"message": "Logout realizado com sucesso!"})

@app.route("/user", methods=["POST"])
#@login_required -> Somente um usuário autenticado no sistema (já cadastrado), pode criar novo usuário
def create_user():

    data  = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
        user = User(username=username, password=hashed_password, role='user')
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "Usuário cadastrado com sucesso!"})

    return jsonify({"ERROR": "Dados Inválidos!"}), 400    

@app.route('/user/<int:id_user>', methods=["GET"])
@login_required
def read_user(id_user):
    user = User.query.get(id_user)

    if user:
        return {"username": user.username}
    return jsonify({"ERROR": "Usuário não encontrado!"}), 404

@app.route('/user/<int:id_user>', methods=["PUT"])
@login_required
def update_user(id_user):
    data = request.json
    user = User.query.get(id_user)

  #Gerenciamento de perfil -> somente atualiza quando id e user = admin

    if id_user != current_user.id and current_user.role == "user":
        return jsonify({"ERROR": "Operação não permitida!"}), 403

    if user and data.get("password"): 
        user.password = data.get("password")
        db.session.commit()

        return jsonify({"message": f"Usuário {id_user} atualizado com sucesso"})
    
    return jsonify({"ERROR": "Usuário não encontrado!"}), 404

@app.route('/user/<int:id_user>', methods=["DELETE"])
@login_required
def read_delete_user(id_user):
    user = User.query.get(id_user)

    #Gerenciamento de perfil -> somente deleta quando user = admin
    if current_user.role != "admin":
       return jsonify({"ERROR": "Operação não permitida!"}), 403 

    if id_user == current_user.id:
        return jsonify({"message": f"Deleção não permitida!!!"}), 403
    
    if user:
        db.session.delete(user) 
        db.session.commit()
        return jsonify({"message": f"Usuário {id_user} deletado com sucesso"})
    
    return jsonify({"ERROR": "Usuário não encontrado!"}), 404

if __name__ == '__main__':
    app.run(debug=True)