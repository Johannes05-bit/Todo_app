from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Configuración de la base de datos y seguridad
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///razas_perros.db'
app.config['SECRET_KEY'] = 'tu_secreto_seguros'
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Modelo de Usuario
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)

class RazaPerro(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    tamaño = db.Column(db.String(50), nullable=False)
    edad = db.Column(db.Integer, nullable=False)

# Crear las tablas
with app.app_context():
    db.create_all()
    

    # Crear usuario por defecto (admin)
    if not User.query.filter_by(username="admin").first():
        hashed_password = generate_password_hash("admin2025")
        admin = User(username="admin", password=hashed_password)
        db.session.add(admin)
        db.session.commit()

# Gestión de usuarios
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        return render_template('login.html', error='Usuario o contraseña inválidos')
    return render_template('login.html')

@app.route('/')
@login_required 
def index():
    razas = RazaPerro.query.all()
    return render_template('index.html', razas=razas)

@app.route('/agregar', methods=['POST'])
def agregar():
    nombre = request.form.get('nombre')
    tamaño = request.form.get('tamaño')
    edad = request.form.get('edad')

    nueva_raza = RazaPerro(nombre=nombre, tamaño=tamaño, edad=edad)
    db.session.add(nueva_raza)
    db.session.commit()
    return redirect(url_for('index'))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return render_template("logout.html")

@app.route('/eliminar/<int:id>', methods=['POST'])
def eliminar(id):
    raza = RazaPerro.query.get(id)
    if raza:
        db.session.delete(raza)
        db.session.commit()
    return redirect(url_for('index'))

@app.errorhandler(401)
def unauthorized_error(e):
    return redirect(url_for("login"))

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error404.html'), 404

@app.route('/cv')
def cv():
    return render_template('cv.html')

if __name__ == '__main__':
    app.run(debug=True)
