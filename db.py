from app import app, db

# Iniciando o contexto da aplicação
with app.app_context():
    db.create_all()
