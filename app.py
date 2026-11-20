from datetime import datetime
from functools import wraps
from pathlib import Path
import os
import sqlite3
import secrets

from flask import (Flask, render_template, request, redirect, url_for,
                   flash, session, jsonify)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / 'pec.db'
UPLOAD_DIR = BASE_DIR / 'static' / 'reportes'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('PEC_SECRET_KEY', 'cambia-esta-clave-antes-de-publicar-pec')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = str(UPLOAD_DIR)


def conectar():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


def crear_tablas():
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    with conectar() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            correo TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            rol TEXT NOT NULL DEFAULT 'usuario',
            fecha_registro TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS reportes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            folio TEXT NOT NULL UNIQUE,
            usuario_id INTEGER,
            nombre TEXT NOT NULL,
            rol_reportante TEXT NOT NULL,
            contacto TEXT,
            tipo_riesgo TEXT NOT NULL,
            ubicacion TEXT NOT NULL,
            fecha_observacion TEXT NOT NULL,
            urgencia TEXT NOT NULL,
            descripcion TEXT NOT NULL,
            evidencia TEXT,
            estado TEXT NOT NULL DEFAULT 'Pendiente',
            fecha_envio TEXT NOT NULL,
            FOREIGN KEY(usuario_id) REFERENCES usuarios(id) ON DELETE SET NULL
        );
        ''')


def requiere_login(func):
    @wraps(func)
    def envoltura(*args, **kwargs):
        if 'usuario_id' not in session:
            flash('Inicia sesión para continuar.', 'warning')
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return envoltura


def requiere_admin(func):
    @wraps(func)
    def envoltura(*args, **kwargs):
        if 'usuario_id' not in session:
            flash('Inicia sesión como administrador.', 'warning')
            return redirect(url_for('login'))
        if session.get('rol') != 'admin':
            flash('Esta sección es exclusiva para administración.', 'danger')
            return redirect(url_for('inicio'))
        return func(*args, **kwargs)
    return envoltura


def extension_permitida(nombre):
    return '.' in nombre and nombre.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.context_processor
def datos_globales():
    return {'usuario_actual': session.get('nombre'), 'rol_actual': session.get('rol')}


@app.route('/')
def inicio():
    return render_template('index.html')


@app.route('/riesgos')
def riesgos():
    return render_template('riesgos.html')


@app.route('/juego')
def juego():
    return render_template('juego.html')


@app.route('/reporte', methods=['GET', 'POST'])
def reporte():
    if request.method == 'POST':
        anonimo = request.form.get('anonimo') == '1'
        nombre = 'Anónimo' if anonimo else request.form.get('nombre', '').strip()
        rol = 'No especificado' if anonimo else request.form.get('rol', '').strip()
        tipo = request.form.get('tipo_riesgo', '').strip()
        ubicacion = request.form.get('ubicacion', '').strip()
        fecha = request.form.get('fecha', '').strip()
        urgencia = request.form.get('urgencia', '').strip()
        descripcion = request.form.get('descripcion', '').strip()
        contacto = '' if anonimo else request.form.get('contacto', '').strip()

        if not all([nombre, rol, tipo, ubicacion, fecha, urgencia, descripcion]):
            return jsonify(ok=False, mensaje='Completa todos los campos obligatorios.'), 400

        evidencia = request.files.get('evidencia')
        nombre_archivo = None
        if evidencia and evidencia.filename:
            if not extension_permitida(evidencia.filename):
                return jsonify(ok=False, mensaje='La evidencia debe ser JPG, JPEG, PNG o WEBP.'), 400
            nombre_archivo = secure_filename(f"{datetime.now():%Y%m%d%H%M%S%f}_{evidencia.filename}")
            evidencia.save(UPLOAD_DIR / nombre_archivo)

        with conectar() as db:
            folio = f'PEC-{datetime.now():%Y}-{secrets.token_hex(3).upper()}'
            db.execute('''INSERT INTO reportes
                (folio, usuario_id, nombre, rol_reportante, contacto, tipo_riesgo,
                 ubicacion, fecha_observacion, urgencia, descripcion, evidencia, estado, fecha_envio)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pendiente', ?)''',
                (folio, session.get('usuario_id'), nombre, rol, contacto, tipo,
                 ubicacion, fecha, urgencia, descripcion, nombre_archivo,
                 datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        return jsonify(ok=True, folio=folio, nombre=nombre, rol=rol, tipo=tipo,
                       ubicacion=ubicacion, fecha=fecha, urgencia=urgencia,
                       descripcion=descripcion)
    return render_template('reporte.html')


@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        correo = request.form.get('correo', '').strip().lower()
        password = request.form.get('password', '')
        confirmar = request.form.get('confirmar', '')
        if not nombre or not correo or not password:
            flash('Completa todos los campos.', 'danger')
        elif len(password) < 8:
            flash('La contraseña debe tener al menos 8 caracteres.', 'danger')
        elif password != confirmar:
            flash('Las contraseñas no coinciden.', 'danger')
        else:
            try:
                with conectar() as db:
                    db.execute('INSERT INTO usuarios (nombre, correo, password_hash, rol, fecha_registro) VALUES (?, ?, ?, ?, ?)',
                               (nombre, correo, generate_password_hash(password), 'usuario', datetime.now().isoformat(timespec='seconds')))
                flash('Tu cuenta fue creada. Ya puedes iniciar sesión.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Ese correo ya está registrado.', 'danger')
    return render_template('registro.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        correo = request.form.get('correo', '').strip().lower()
        password = request.form.get('password', '')
        with conectar() as db:
            usuario = db.execute('SELECT * FROM usuarios WHERE correo = ?', (correo,)).fetchone()
        if usuario and check_password_hash(usuario['password_hash'], password):
            session.clear()
            session['usuario_id'] = usuario['id']
            session['nombre'] = usuario['nombre']
            session['rol'] = usuario['rol']
            flash(f"Bienvenido/a, {usuario['nombre']}.", 'success')
            return redirect(url_for('admin_panel') if usuario['rol'] == 'admin' else url_for('inicio'))
        flash('Correo o contraseña incorrectos.', 'danger')
    return render_template('login.html')


@app.route('/cerrar-sesion')
def cerrar_sesion():
    session.clear()
    flash('Cerraste sesión correctamente.', 'success')
    return redirect(url_for('inicio'))


@app.route('/admin')
@requiere_admin
def admin_panel():
    with conectar() as db:
        reportes = db.execute('SELECT * FROM reportes ORDER BY CASE urgencia WHEN "🔴 Alta (Peligro inminente de accidente)" THEN 1 WHEN "🟡 Media (Requiere atención pronta)" THEN 2 ELSE 3 END, id DESC').fetchall()
        usuarios = db.execute('SELECT id, nombre, correo, rol, fecha_registro FROM usuarios ORDER BY id DESC').fetchall()
    return render_template('admin.html', reportes=reportes, usuarios=usuarios)


@app.route('/admin/reporte/<int:reporte_id>/estado', methods=['POST'])
@requiere_admin
def cambiar_estado(reporte_id):
    estado = request.form.get('estado', '')
    if estado not in {'Pendiente', 'En revisión', 'Atendido'}:
        flash('Estado no válido.', 'danger')
    else:
        with conectar() as db:
            db.execute('UPDATE reportes SET estado = ? WHERE id = ?', (estado, reporte_id))
        flash('Se actualizó el estado del reporte.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/seguimiento', methods=['GET', 'POST'])
def seguimiento():
    resultado = None
    if request.method == 'POST':
        folio = request.form.get('folio', '').strip().upper()
        with conectar() as db:
            resultado = db.execute('SELECT folio, estado, tipo_riesgo, ubicacion, fecha_envio FROM reportes WHERE folio = ?', (folio,)).fetchone()
        if not resultado:
            flash('No encontramos ese folio. Verifica que esté escrito correctamente.', 'warning')
    return render_template('seguimiento.html', resultado=resultado)


@app.route('/nosotros')
def nosotros():
    return render_template('nosotros.html')


@app.route('/conocenos')
def conocenos():
    return render_template('conocenos.html')


@app.errorhandler(413)
def archivo_demasiado_grande(error):
    if request.path == '/reporte':
        return jsonify(ok=False, mensaje='La imagen supera el límite de 5 MB.'), 413
    return 'El archivo supera el límite de 5 MB.', 413


crear_tablas()

if __name__ == '__main__':
    app.run(debug=True)
