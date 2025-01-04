from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os

# Inicializando o app Flask
app = Flask(__name__)

# Configurações do banco de dados e segredo da aplicação
app.config['SECRET_KEY'] = 'cfc5d72c1029ebefc518a5485d8db1593b08d75d3073e375'

# Usando SQLite como banco de dados
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('postgresql://fluxo_caixa_user:PD4jbKbqlqvYx5seEQorj89UlKTixv09@dpg-ctsb1ua3esus73doo21g-a/fluxo_caixa') or 'sqlite:///fluxo_caixa.db'
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

# Modelo de Usuário
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

# Modelo de Despesa
class Despesa(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    categoria = db.Column(db.String(50), nullable=False)
    valor = db.Column(db.Float, nullable=False)
    descricao = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user = db.relationship('User', backref=db.backref('despesas', lazy=True))

# Função para criar o banco de dados e as tabelas antes do primeiro pedido
@app.before_request
def create_tables():
    db.create_all()

# Página Inicial
@app.route('/')
@login_required
def index():
    despesas = Despesa.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', despesas=despesas)

# Rota de Cadastro
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Verificar se o nome de usuário já existe
        user_exists = User.query.filter_by(username=username).first()
        if user_exists:
            flash('O nome de usuário já está em uso!', 'danger')
            return redirect(url_for('register'))
        
        # Criptografando a senha (usando o padrão pbkdf2:sha256)
        hashed_password = generate_password_hash(password)
        
        # Criando um novo usuário
        new_user = User(username=username, password=hashed_password)
        
        try:
            # Adicionando no banco de dados
            db.session.add(new_user)
            db.session.commit()
            flash('Cadastro realizado com sucesso!', 'success')
            return redirect(url_for('login'))  # Redirecionar para a página de login após o cadastro
        except Exception as e:
            db.session.rollback()  # Reverter qualquer alteração em caso de erro
            flash(f'Erro ao cadastrar o usuário: {e}', 'danger')
            return redirect(url_for('register'))
    
    return render_template('register.html')

# Rota de Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
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
