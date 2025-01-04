from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user

# Inicializando o app Flask
app = Flask(__name__)

# Configurações do banco de dados e segredo da aplicação
app.config['SECRET_KEY'] = 'mysecretkey'

# Usando SQLite como banco de dados
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fluxo_caixa.db'  # O banco será um arquivo .db na pasta do projeto
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializando o banco de dados
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Função para carregar usuário para o login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Função para definir o modelo de Usuário no banco de dados
def criar_usuario(username, password):
    usuario = User(username=username, password=password)
    db.session.add(usuario)
    db.session.commit()

# Função para definir o modelo de Despesa no banco de dados
def criar_despesa(categoria, valor, descricao, user_id):
    despesa = Despesa(categoria=categoria, valor=valor, descricao=descricao, user_id=user_id)
    db.session.add(despesa)
    db.session.commit()

# Modelo de Usuário (sem usar classe, apenas função para criar)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

# Modelo de Despesa (sem usar classe, apenas função)
class Despesa(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    categoria = db.Column(db.String(50), nullable=False)
    valor = db.Column(db.Float, nullable=False)
    descricao = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user = db.relationship('User', backref=db.backref('despesas', lazy=True))

# Página Inicial (exibe as despesas)
@app.route('/')
@login_required
def index():
    despesas = Despesa.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', despesas=despesas)

# Rota de Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.password == password:  # Aqui, utilize hashing de senhas em produção
            login_user(user)
            return redirect(url_for('index'))
        else:
            return "Usuário ou senha inválidos", 401

    return render_template('login.html')

# Rota de Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Rota para adicionar uma despesa
@app.route('/add', methods=['POST'])
@login_required
def add_despesa():
    categoria = request.form['categoria']
    valor = request.form['valor']
    descricao = request.form['descricao']
    criar_despesa(categoria, valor, descricao, current_user.id)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
