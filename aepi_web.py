from flask import Flask, render_template, request, redirect, url_for, flash, abort, session, send_from_directory
import os
from datetime import datetime, timedelta
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import timedelta
from flask_session import Session

app = Flask(__name__)

if not os.path.exists(app.instance_path):
    os.makedirs(app.instance_path)
    
# Configuración de la aplicación
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'usuarios.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["SECRET_KEY"] = "una_clave_muy_segura"
app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=7) 
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem" 
app.config["SESSION_FILE_DIR"] = "./flask_session" 
app.config["SESSION_USE_SIGNER"] = True

# Configuración de uploads y extensiones permitidas
UPLOAD_FOLDER = os.path.abspath(os.path.join(os.path.dirname(__file__), "uploads"))
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ALLOWED_EXTENSIONS'] = ALLOWED_EXTENSIONS

Session(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Modelo de Usuario
class Usuario(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)

    def check_password(self, password):
        return check_password_hash(self.password, password)

# Crear la base de datos
with app.app_context():
    db.create_all()

@app.context_processor
def inject_user():
    return dict(current_user=current_user)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route("/debug_session")
def debug_session():
    return f"Usuario autenticado: {current_user.is_authenticated}"

# Rutas principales
@app.route("/")
def home():
    return render_template("home.html")

@app.route("/proyectos")
def proyectos():
    return render_template("proyectos.html")

@app.route("/recepcion_a_proyectos", methods=['GET', 'POST'])
def recepcion_a_proyectos():
    if request.method == 'POST':
        nombre = request.form.get('nombre')
        numero = request.form.get('numero')
        numero2 = request.form.get('numero2')
        archivo = request.files['archivo']
        if archivo and allowed_file(archivo.filename):
            fecha_actual = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{numero}_{numero2}_{nombre}_{fecha_actual}_{archivo.filename}"
            archivo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('confirmacion'))
        else:
            flash('El archivo no tiene un formato permitido.', 'error')
    return render_template("recepcion_a_proyectos.html")

@app.route("/documentacion")
def documentacion():
    return render_template("documentacion.html")

@app.route('/documentos')
def documentos():
    ruta_docs = os.path.join(app.root_path, 'static', 'docs')
    
    try:
        archivos = os.listdir(ruta_docs)
        archivos = [archivo for archivo in archivos if os.path.isfile(os.path.join(ruta_docs, archivo))]
    except FileNotFoundError:
        archivos = []

    print("Archivos encontrados:", archivos)
    
    return render_template('documentos.html', archivos=archivos)

@app.route("/confirmacion")
def confirmacion():
    return render_template("confirmacion.html")

# Función para cargar el usuario
@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

# Ruta de login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = Usuario.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user, remember=True)
            session["user_id"] = user.id  
            session.permanent = True 
            flash("Inicio de sesión exitoso", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Usuario o contraseña incorrectos", "danger")

    return render_template("login.html")

# Ruta de logout
@app.route("/logout")
def logout():
    session.pop("user_id", None) 
    logout_user()
    flash("Has cerrado sesión correctamente", "info")
    return redirect(url_for("login"))

# Rutas de administración
@app.route("/admin/usuarios", methods=['GET', 'POST'])
@login_required
def admin_usuarios():
    if not current_user.is_admin:
        abort(403)
    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")
        if Usuario.query.filter_by(username=username).first():
            flash("El usuario ya existe.", "danger")
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            nuevo_usuario = Usuario(username=username, password=hashed_password)
            db.session.add(nuevo_usuario)
            db.session.commit()
            flash("Usuario agregado correctamente.", "success")
    usuarios = Usuario.query.all()
    return render_template("admin_usuarios.html", usuarios=usuarios)

@app.route("/admin/eliminar_usuario/<int:user_id>")
@login_required
def eliminar_usuario(user_id):
    if not current_user.is_admin:
        abort(403)
    usuario = Usuario.query.get(user_id)
    if usuario:
        db.session.delete(usuario)
        db.session.commit()
        flash("Usuario eliminado.", "info")
    else:
        flash("Usuario no encontrado.", "danger")
    return redirect(url_for("admin_usuarios"))

@app.route("/dashboard")
def dashboard():
    archivos = []
    
    # Obtener archivos con fecha de modificación
    if os.path.exists(UPLOAD_FOLDER):
        for archivo in os.listdir(UPLOAD_FOLDER):
            ruta_archivo = os.path.join(UPLOAD_FOLDER, archivo)
            if os.path.isfile(ruta_archivo):
                fecha_modificacion = datetime.fromtimestamp(os.path.getmtime(ruta_archivo)).strftime('%Y-%m-%d %H:%M')
                archivos.append({"nombre": archivo, "fecha": fecha_modificacion})

    # Ordenar archivos por fecha más reciente
    archivos.sort(key=lambda x: x["fecha"], reverse=True)

    # Agrupar por fecha
    archivos_por_fecha = {}
    for archivo in archivos:
        fecha_key = archivo["fecha"].split(" ")[0]
        if fecha_key not in archivos_por_fecha:
            archivos_por_fecha[fecha_key] = []
        archivos_por_fecha[fecha_key].append(archivo)

    return render_template("dashboard.html", archivos_por_fecha=archivos_por_fecha)

@app.route("/uploads/<filename>")
def get_uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# INICIO DEL SERVIDOR
if __name__ == "__main__":
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)
