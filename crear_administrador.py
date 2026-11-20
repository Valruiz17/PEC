"""Crea la primera cuenta administradora del PEC desde la terminal."""
from getpass import getpass
from datetime import datetime
from app import conectar, crear_tablas
from werkzeug.security import generate_password_hash

crear_tablas()
nombre = input('Nombre de la persona administradora: ').strip()
correo = input('Correo de administración: ').strip().lower()
password = getpass('Contraseña (mínimo 8 caracteres): ')
confirmar = getpass('Confirma la contraseña: ')
if not nombre or not correo or len(password) < 8 or password != confirmar:
    raise SystemExit('Datos incompletos, contraseña corta o contraseñas diferentes. No se creó la cuenta.')
try:
    with conectar() as db:
        db.execute('INSERT INTO usuarios (nombre, correo, password_hash, rol, fecha_registro) VALUES (?, ?, ?, ?, ?)',
                   (nombre, correo, generate_password_hash(password), 'admin', datetime.now().isoformat(timespec='seconds')))
    print('Cuenta administradora creada. Ya puedes iniciar sesión en /login.')
except Exception as error:
    raise SystemExit(f'No se pudo crear la cuenta: {error}')
