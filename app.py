from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import json
import os
from datetime import datetime, timedelta
import uuid
import qrcode
import io
import base64
import time
import logging
from logging.handlers import RotatingFileHandler

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'tu_clave_secreta_aqui')

# Archivos para almacenamiento
USERS_FILE = 'users.json'
PATIENTS_FILE = 'patients.json'
LOGS_FILE = 'logs.txt'
LOGIN_ATTEMPTS_FILE = 'login_attempts.json'

# Versión soportada
SUPPORTED_VERSION = '1.0'

# Configuración de token
TOKEN_EXPIRY_MINUTES = 5

# Configuración de bloqueo de login
MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_DURATION_MINUTES = 5

# Configuración de logging
def setup_logging():
    """Configura el sistema de logging para escribir en archivo de texto"""
    # Crear directorio logs si no existe
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Configurar el logger
    logger = logging.getLogger('app_logger')
    logger.setLevel(logging.INFO)
    
    # Crear handler con rotación de archivos (máximo 10MB, mantener 5 backups)
    file_handler = RotatingFileHandler(
        LOGS_FILE, 
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    
    # Formato del log
    formatter = logging.Formatter(
        '%(asctime)s | %(levelname)s | IP: %(ip)s | Route: %(route)s | Result: %(result)s | User: %(user)s'
    )
    file_handler.setFormatter(formatter)
    
    # Agregar handler al logger
    logger.addHandler(file_handler)
    
    return logger

# Inicializar logger
app_logger = setup_logging()

# Función para escribir en el log de auditoría
def write_log(ruta, resultado, usuario=None):
    """Escribe una entrada en el log de auditoría en formato texto"""
    ip = request.remote_addr or 'unknown'
    usuario = usuario or 'anonymous'
    
    # Usar el logger configurado
    app_logger.info(
        '', 
        extra={
            'ip': ip,
            'route': ruta,
            'result': resultado,
            'user': usuario
        }
    )

# Funciones para manejar intentos de login
def load_login_attempts():
    """Carga los intentos de login desde archivo JSON"""
    try:
        if os.path.exists(LOGIN_ATTEMPTS_FILE):
            with open(LOGIN_ATTEMPTS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}
    except Exception as e:
        print(f"Error cargando intentos de login: {e}")
        return {}

def save_login_attempts(attempts):
    """Guarda los intentos de login en archivo JSON"""
    try:
        with open(LOGIN_ATTEMPTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(attempts, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Error guardando intentos de login: {e}")
        return False

def get_login_attempts(username):
    """Obtiene los intentos de login para un usuario específico"""
    attempts = load_login_attempts()
    return attempts.get(username, {
        'failed_attempts': 0,
        'blocked_until': None,
        'last_attempt': None
    })

def increment_failed_attempts(username):
    """Incrementa el contador de intentos fallidos para un usuario"""
    attempts = load_login_attempts()
    
    if username not in attempts:
        attempts[username] = {
            'failed_attempts': 0,
            'blocked_until': None,
            'last_attempt': None
        }
    
    attempts[username]['failed_attempts'] += 1
    attempts[username]['last_attempt'] = datetime.now().isoformat()
    
    # Si alcanza el máximo de intentos, bloquear usuario
    if attempts[username]['failed_attempts'] >= MAX_LOGIN_ATTEMPTS:
        blocked_until = datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        attempts[username]['blocked_until'] = blocked_until.isoformat()
    
    save_login_attempts(attempts)
    return attempts[username]

def reset_failed_attempts(username):
    """Resetea los intentos fallidos para un usuario (login exitoso)"""
    attempts = load_login_attempts()
    
    if username in attempts:
        attempts[username] = {
            'failed_attempts': 0,
            'blocked_until': None,
            'last_attempt': None
        }
        save_login_attempts(attempts)

def is_user_blocked(username):
    """Verifica si un usuario está bloqueado"""
    user_attempts = get_login_attempts(username)
    
    if user_attempts['blocked_until']:
        blocked_until = datetime.fromisoformat(user_attempts['blocked_until'])
        if datetime.now() < blocked_until:
            return True, blocked_until
        else:
            # El bloqueo ha expirado, resetear
            reset_failed_attempts(username)
            return False, None
    
    return False, None

def get_remaining_lockout_time(username):
    """Obtiene el tiempo restante de bloqueo en segundos"""
    user_attempts = get_login_attempts(username)
    
    if user_attempts['blocked_until']:
        blocked_until = datetime.fromisoformat(user_attempts['blocked_until'])
        now = datetime.now()
        if now < blocked_until:
            return (blocked_until - now).total_seconds()
    
    return 0

# Función para leer logs desde el archivo de texto
def read_logs(limit=100):
    """Lee las últimas 'limit' líneas del archivo de logs"""
    try:
        if not os.path.exists(LOGS_FILE):
            return []
        
        with open(LOGS_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            # Retornar las últimas 'limit' líneas
            return lines[-limit:] if len(lines) > limit else lines
    except Exception as e:
        print(f"Error leyendo logs: {e}")
        return []

# Función para parsear una línea de log
def parse_log_line(line):
    """Parsea una línea de log y devuelve un diccionario"""
    try:
        # Ejemplo de línea:
        # 2024-01-01 10:00:00,123 | INFO | IP: 127.0.0.1 | Route: /login | Result: OK - Login exitoso | User: admin
        parts = line.strip().split(' | ')
        if len(parts) >= 5:
            timestamp = parts[0]
            level = parts[1]
            ip = parts[2].replace('IP: ', '')
            route = parts[3].replace('Route: ', '')
            result = parts[4].replace('Result: ', '')
            user = parts[5].replace('User: ', '') if len(parts) > 5 else 'anonymous'
            
            return {
                'timestamp': timestamp,
                'level': level,
                'ip': ip,
                'route': route,
                'result': result,
                'user': user
            }
    except Exception as e:
        print(f"Error parseando línea de log: {e}")
    
    return None

# Función para generar token con expiración
def generate_session_token():
    return {
        'token': str(uuid.uuid4()),
        'expires_at': (datetime.now() + timedelta(minutes=TOKEN_EXPIRY_MINUTES)).isoformat(),
        'created_at': datetime.now().isoformat()
    }

# Función para verificar si el token ha expirado
def is_token_expired(token_data):
    if not token_data or 'expires_at' not in token_data:
        return True
    
    try:
        expires_at = datetime.fromisoformat(token_data['expires_at'])
        return datetime.now() > expires_at
    except (ValueError, TypeError):
        return True

# Función para renovar token (SIN verificar expiración)
def refresh_session_token():
    if 'user_id' in session:
        new_token = generate_session_token()
        session['session_token'] = new_token
        write_log('/refresh_token', f'OK - Token renovado', session.get('username'))
        return new_token
    return None

# Decorador para validar versión
def validate_version(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Buscar versión en JSON body
        version = None
        if request.is_json and request.json:
            version = request.json.get('version')
        
        # Si no está en JSON, buscar en query string
        if not version:
            version = request.args.get('version')
        
        if not version:
            write_log(request.path, "ERROR - Version no proporcionada")
            return jsonify({"error": "Parámetro 'version' requerido"}), 400
        
        if version != SUPPORTED_VERSION:
            write_log(request.path, f"ERROR - Version no soportada: {version}")
            return jsonify({"error": "Version no soportada, actualice su cliente"}), 400
        
        return f(*args, **kwargs)
    return decorated_function

# Decorador para verificar login y token
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            write_log(request.path, "ERROR - No autenticado")
            if request.path.startswith('/api/'):
                return jsonify({"error": "No autenticado"}), 401
            return redirect(url_for('login'))
        
        # Verificar token de sesión
        token_data = session.get('session_token')
        if not token_data or is_token_expired(token_data):
            write_log(request.path, "ERROR - Token expirado", session.get('username'))
            session.clear()
            if request.path.startswith('/api/'):
                return jsonify({"error": "Token expirado"}), 401
            flash('Su sesión ha expirado. Por favor, inicie sesión nuevamente.')
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

# Decorador especial para refresh que NO verifica expiración
def login_required_no_token_check(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            write_log(request.path, "ERROR - No autenticado")
            return jsonify({"success": False, "message": "No autenticado"}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# Funciones para manejar usuarios
def load_users():
    try:
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}
    except Exception as e:
        print(f"Error cargando usuarios: {e}")
        return {}

def save_users(users):
    try:
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Error guardando usuarios: {e}")
        return False

def save_user(username, password, email):
    users = load_users()
    users[username] = {
        'password': password,
        'email': email,
        'created_at': datetime.now().isoformat()
    }
    return save_users(users)

# Funciones para manejar pacientes
def load_patients():
    try:
        if os.path.exists(PATIENTS_FILE):
            with open(PATIENTS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}
    except Exception as e:
        print(f"Error cargando pacientes: {e}")
        return {}

def save_patients(patients):
    try:
        with open(PATIENTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(patients, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Error guardando pacientes: {e}")
        return False

def save_patient(patient_id, name, age, symptoms, created_by=None, updated_by=None):
    patients = load_patients()
    
    if patient_id in patients:
        # Actualizar paciente existente
        patients[patient_id]['name'] = name
        patients[patient_id]['age'] = int(age)
        patients[patient_id]['symptoms'] = symptoms
        patients[patient_id]['updated_at'] = datetime.now().isoformat()
        patients[patient_id]['updated_by'] = updated_by
    else:
        # Crear nuevo paciente
        patients[patient_id] = {
            'name': name,
            'age': int(age),
            'symptoms': symptoms,
            'created_at': datetime.now().isoformat(),
            'created_by': created_by,
            'updated_at': None,
            'updated_by': None
        }
    
    return save_patients(patients)

def delete_patient(patient_id):
    patients = load_patients()
    if patient_id in patients:
        del patients[patient_id]
        return save_patients(patients)
    return False

# Rutas principales
@app.route('/')
def index():
    write_log('/', 'OK')
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Initialize failed_attempts for GET requests and all scenarios
    failed_attempts = 0
    error_message = None
    blocked_until = None
    remaining_seconds = 0
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Usuario y contraseña son requeridos')
            return render_template('login.html', 
                                 failed_attempts=failed_attempts,
                                 error_message=error_message,
                                 blocked_until=blocked_until,
                                 remaining_seconds=remaining_seconds)
        
        # Get current failed attempts for this user
        user_attempts = get_login_attempts(username)
        failed_attempts = user_attempts['failed_attempts']
        
        # Verificar si el usuario está bloqueado
        is_blocked, blocked_until_dt = is_user_blocked(username)
        if is_blocked:
            remaining_time = get_remaining_lockout_time(username)
            write_log('/login', f'ERROR - Usuario bloqueado: {username}', username)
            return render_template('login.html', 
                                 error_message=f'Cuenta bloqueada por {LOCKOUT_DURATION_MINUTES} minutos debido a demasiados intentos fallidos.',
                                 blocked_until=blocked_until_dt.isoformat(),
                                 remaining_seconds=remaining_time,
                                 failed_attempts=failed_attempts)
        
        users = load_users()
        
        if username in users and check_password_hash(users[username]['password'], password):
            # Login exitoso - resetear intentos fallidos
            reset_failed_attempts(username)
            session['user_id'] = username
            session['username'] = username
            session['session_token'] = generate_session_token()
            write_log('/login', f'OK - Login exitoso', username)
            return redirect(url_for('dashboard'))
        else:
            # Login fallido - incrementar intentos fallidos
            user_attempts = increment_failed_attempts(username)
            failed_attempts = user_attempts['failed_attempts']
            write_log('/login', f'ERROR - Credenciales incorrectas para {username} - Intento {failed_attempts}/{MAX_LOGIN_ATTEMPTS}', username)
            
            if failed_attempts >= MAX_LOGIN_ATTEMPTS:
                # Usuario bloqueado
                blocked_until_dt = datetime.fromisoformat(user_attempts['blocked_until'])
                remaining_time = get_remaining_lockout_time(username)
                return render_template('login.html', 
                                     error_message=f'Demasiados intentos fallidos. Cuenta bloqueada por {LOCKOUT_DURATION_MINUTES} minutos.',
                                     blocked_until=blocked_until_dt.isoformat(),
                                     remaining_seconds=remaining_time,
                                     failed_attempts=failed_attempts)
            else:
                # Mostrar advertencia
                return render_template('login.html', 
                                     error_message='Usuario o contraseña incorrectos.',
                                     failed_attempts=failed_attempts,
                                     blocked_until=blocked_until,
                                     remaining_seconds=remaining_seconds)
    
    # GET request - show login form with default values
    return render_template('login.html', 
                         failed_attempts=failed_attempts,
                         error_message=error_message,
                         blocked_until=blocked_until,
                         remaining_seconds=remaining_seconds)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        email = request.form.get('email', '').strip()
        
        if not all([username, password, email]):
            flash('Todos los campos son requeridos')
            return render_template('register.html')
        
        users = load_users()
        
        if username in users:
            write_log('/register', f'ERROR - Usuario ya existe: {username}')
            flash('El usuario ya existe')
        else:
            if save_user(username, generate_password_hash(password), email):
                write_log('/register', f'OK - Usuario registrado: {username}')
                flash('Usuario registrado exitosamente')
                return redirect(url_for('login'))
            else:
                flash('Error al registrar usuario')
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    patients = load_patients()
    write_log('/dashboard', 'OK - Acceso a dashboard', session['username'])
    return render_template('dashboard.html', patients=patients)

@app.route('/logout')
def logout():
    username = session.get('username', 'Unknown')
    session.clear()
    write_log('/logout', f'OK - Logout', username)
    return redirect(url_for('index'))

# Ruta para ver logs
@app.route('/logs')
@login_required
def view_logs():
    log_lines = read_logs(limit=200)  # Mostrar últimas 200 líneas
    logs = []
    
    # Parsear las líneas de log
    for line in reversed(log_lines):  # Mostrar más recientes primero
        parsed_log = parse_log_line(line)
        if parsed_log:
            logs.append(parsed_log)
    
    write_log('/logs', 'OK - Consulta de logs', session['username'])
    return render_template('logs.html', logs=logs)

# Ruta para refrescar token (SIN verificar expiración del token)
@app.route('/refresh_token', methods=['POST'])
@login_required_no_token_check
def refresh_token():
    new_token = refresh_session_token()
    if new_token:
        return jsonify({
            "success": True,
            "message": "Token renovado exitosamente",
            "expires_at": new_token['expires_at']
        }), 200
    else:
        return jsonify({"success": False, "message": "Error al renovar token"}), 400

# Ruta para verificar estado del token
@app.route('/check_token', methods=['GET'])
@login_required
def check_token():
    token_data = session.get('session_token')
    if token_data:
        try:
            expires_at = datetime.fromisoformat(token_data['expires_at'])
            now = datetime.now()
            remaining_seconds = (expires_at - now).total_seconds()
            
            return jsonify({
                "valid": True,
                "expires_at": token_data['expires_at'],
                "remaining_seconds": max(0, remaining_seconds)
            }), 200
        except (ValueError, TypeError):
            return jsonify({"valid": False}), 401
    else:
        return jsonify({"valid": False}), 401

# API para obtener información de bloqueo de usuario
@app.route('/api/user_lockout_status/<username>', methods=['GET'])
def api_user_lockout_status(username):
    """API para verificar el estado de bloqueo de un usuario"""
    is_blocked, blocked_until = is_user_blocked(username)
    user_attempts = get_login_attempts(username)
    
    result = {
        "username": username,
        "is_blocked": is_blocked,
        "failed_attempts": user_attempts['failed_attempts'],
        "max_attempts": MAX_LOGIN_ATTEMPTS,
        "lockout_duration_minutes": LOCKOUT_DURATION_MINUTES
    }
    
    if is_blocked:
        result["blocked_until"] = blocked_until.isoformat()
        result["remaining_seconds"] = get_remaining_lockout_time(username)
    
    return jsonify(result), 200

# API Endpoints para Postman con soporte para bloqueo
@app.route('/api/register', methods=['POST'])
@validate_version
def api_register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "JSON requerido"}), 400
            
        username = data.get('username', '').strip()
        password = data.get('password', '')
        email = data.get('email', '').strip()
        
        if not all([username, password, email]):
            write_log('/api/register', 'ERROR - Datos incompletos')
            return jsonify({"error": "Faltan datos requeridos"}), 400
        
        users = load_users()
        
        if username in users:
            write_log('/api/register', f'ERROR - Usuario ya existe: {username}')
            return jsonify({"error": "El usuario ya existe"}), 409
        
        if save_user(username, generate_password_hash(password), email):
            write_log('/api/register', f'OK - Usuario registrado via API: {username}')
            return jsonify({"message": "Usuario registrado exitosamente"}), 201
        else:
            return jsonify({"error": "Error al registrar usuario"}), 500
    except Exception as e:
        print(f"Error en api_register: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

@app.route('/api/login', methods=['POST'])
@validate_version
def api_login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "JSON requerido"}), 400
            
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not all([username, password]):
            write_log('/api/login', 'ERROR - Datos incompletos')
            return jsonify({"error": "Username y password requeridos"}), 400
        
        # Verificar si el usuario está bloqueado
        is_blocked, blocked_until = is_user_blocked(username)
        if is_blocked:
            remaining_time = get_remaining_lockout_time(username)
            write_log('/api/login', f'ERROR - Usuario bloqueado API: {username}', username)
            return jsonify({
                "error": "Usuario bloqueado temporalmente",
                "blocked_until": blocked_until.isoformat(),
                "remaining_seconds": remaining_time,
                "lockout_duration_minutes": LOCKOUT_DURATION_MINUTES
            }), 423  # 423 Locked
        
        users = load_users()
        
        if username in users and check_password_hash(users[username]['password'], password):
            # Login exitoso
            reset_failed_attempts(username)
            token = str(uuid.uuid4())  # Token simple para demo
            write_log('/api/login', f'OK - Login API exitoso', username)
            return jsonify({"message": "Login exitoso", "token": token}), 200
        else:
            # Login fallido
            user_attempts = increment_failed_attempts(username)
            write_log('/api/login', f'ERROR - Credenciales incorrectas API para {username} - Intento {user_attempts["failed_attempts"]}/{MAX_LOGIN_ATTEMPTS}', username)
            
            if user_attempts['failed_attempts'] >= MAX_LOGIN_ATTEMPTS:
                # Usuario bloqueado
                blocked_until = datetime.fromisoformat(user_attempts['blocked_until'])
                remaining_time = get_remaining_lockout_time(username)
                return jsonify({
                    "error": "Usuario bloqueado por demasiados intentos fallidos",
                    "blocked_until": blocked_until.isoformat(),
                    "remaining_seconds": remaining_time,
                    "lockout_duration_minutes": LOCKOUT_DURATION_MINUTES
                }), 423  # 423 Locked
            else:
                return jsonify({
                    "error": "Credenciales incorrectas",
                    "failed_attempts": user_attempts['failed_attempts'],
                    "max_attempts": MAX_LOGIN_ATTEMPTS
                }), 401
    except Exception as e:
        print(f"Error en api_login: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

@app.route('/api/patients', methods=['GET', 'POST'])
@validate_version
def api_patients():
    try:
        if request.method == 'GET':
            patients = load_patients()
            write_log('/api/patients', 'OK - Consulta de pacientes via API')
            return jsonify(patients), 200
        
        elif request.method == 'POST':
            data = request.get_json()
            if not data:
                return jsonify({"error": "JSON requerido"}), 400
                
            name = data.get('name', '').strip()
            age = data.get('age')
            symptoms = data.get('symptoms', '').strip()
            
            if not all([name, age, symptoms]):
                write_log('/api/patients', 'ERROR - Datos de paciente incompletos')
                return jsonify({"error": "Faltan datos del paciente"}), 400
            
            try:
                age = int(age)
                if age < 0 or age > 150:
                    return jsonify({"error": "Edad debe ser un número válido entre 0 y 150"}), 400
            except (ValueError, TypeError):
                return jsonify({"error": "Edad debe ser un número válido"}), 400
            
            patient_id = str(uuid.uuid4())
            
            if save_patient(patient_id, name, age, symptoms):
                write_log('/api/patients', f'OK - Paciente registrado via API: {name}')
                return jsonify({"message": "Paciente registrado exitosamente", "patient_id": patient_id}), 201
            else:
                return jsonify({"error": "Error al registrar paciente"}), 500
    except Exception as e:
        print(f"Error en api_patients: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

@app.route('/api/patients/<patient_id>', methods=['GET', 'PUT', 'DELETE'])
@validate_version
def api_patient_operations(patient_id):
    try:
        patients = load_patients()
        
        if patient_id not in patients:
            write_log(f'/api/patients/{patient_id}', 'ERROR - Paciente no encontrado')
            return jsonify({"error": "Paciente no encontrado"}), 404
        
        if request.method == 'GET':
            write_log(f'/api/patients/{patient_id}', 'OK - Consulta de paciente específico')
            return jsonify(patients[patient_id]), 200
        
        elif request.method == 'PUT':
            data = request.get_json()
            if not data:
                return jsonify({"error": "JSON requerido"}), 400
                
            name = data.get('name', '').strip()
            age = data.get('age')
            symptoms = data.get('symptoms', '').strip()
            
            if not all([name, age, symptoms]):
                write_log(f'/api/patients/{patient_id}', 'ERROR - Datos de actualización incompletos')
                return jsonify({"error": "Faltan datos del paciente"}), 400
            
            try:
                age = int(age)
                if age < 0 or age > 150:
                    return jsonify({"error": "Edad debe ser un número válido entre 0 y 150"}), 400
            except (ValueError, TypeError):
                return jsonify({"error": "Edad debe ser un número válido"}), 400
            
            if save_patient(patient_id, name, age, symptoms):
                write_log(f'/api/patients/{patient_id}', f'OK - Paciente actualizado via API: {name}')
                return jsonify({"message": "Paciente actualizado exitosamente"}), 200
            else:
                return jsonify({"error": "Error al actualizar paciente"}), 500
        
        elif request.method == 'DELETE':
            patient_name = patients[patient_id]['name']
            if delete_patient(patient_id):
                write_log(f'/api/patients/{patient_id}', f'OK - Paciente eliminado via API: {patient_name}')
                return jsonify({"message": "Paciente eliminado exitosamente"}), 200
            else:
                return jsonify({"error": "Error al eliminar paciente"}), 500
    except Exception as e:
        print(f"Error en api_patient_operations: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

# Ruta para agregar paciente desde el dashboard
@app.route('/add_patient', methods=['POST'])
@login_required
def add_patient():
    name = request.form.get('name', '').strip()
    age = request.form.get('age', '')
    symptoms = request.form.get('symptoms', '').strip()
    
    if not all([name, age, symptoms]):
        write_log('/add_patient', 'ERROR - Datos de paciente incompletos')
        flash('Todos los campos son requeridos')
        return redirect(url_for('dashboard'))
    
    try:
        age = int(age)
        if age < 0 or age > 150:
            flash('Edad debe ser un número válido entre 0 y 150')
            return redirect(url_for('dashboard'))
    except (ValueError, TypeError):
        flash('Edad debe ser un número válido')
        return redirect(url_for('dashboard'))
    
    patient_id = str(uuid.uuid4())
    
    if save_patient(patient_id, name, age, symptoms, session['username']):
        write_log('/add_patient', f'OK - Paciente agregado: {name}', session['username'])
        flash('Paciente agregado exitosamente')
    else:
        flash('Error al agregar paciente')
    
    return redirect(url_for('dashboard'))

# Ruta para editar paciente desde el dashboard
@app.route('/edit_patient/<patient_id>', methods=['GET', 'POST'])
@login_required
def edit_patient(patient_id):
    patients = load_patients()
    
    if patient_id not in patients:
        write_log(f'/edit_patient/{patient_id}', 'ERROR - Paciente no encontrado')
        flash('Paciente no encontrado')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        age = request.form.get('age', '')
        symptoms = request.form.get('symptoms', '').strip()
        
        if not all([name, age, symptoms]):
            write_log(f'/edit_patient/{patient_id}', 'ERROR - Datos de actualización incompletos')
            flash('Todos los campos son requeridos')
            return render_template('edit_patient.html', patient=patients[patient_id], patient_id=patient_id)
        
        try:
            age = int(age)
            if age < 0 or age > 150:
                flash('Edad debe ser un número válido entre 0 y 150')
                return render_template('edit_patient.html', patient=patients[patient_id], patient_id=patient_id)
        except (ValueError, TypeError):
            flash('Edad debe ser un número válido')
            return render_template('edit_patient.html', patient=patients[patient_id], patient_id=patient_id)
        
        if save_patient(patient_id, name, age, symptoms, updated_by=session['username']):
            write_log(f'/edit_patient/{patient_id}', f'OK - Paciente actualizado: {name}', session['username'])
            flash('Paciente actualizado exitosamente')
        else:
            flash('Error al actualizar paciente')
        
        return redirect(url_for('dashboard'))
    
    write_log(f'/edit_patient/{patient_id}', 'OK - Formulario de edición mostrado', session['username'])
    return render_template('edit_patient.html', patient=patients[patient_id], patient_id=patient_id)

# Ruta para eliminar paciente desde el dashboard
@app.route('/delete_patient/<patient_id>')
@login_required
def delete_patient_route(patient_id):
    patients = load_patients()
    
    if patient_id not in patients:
        write_log(f'/delete_patient/{patient_id}', 'ERROR - Paciente no encontrado')
        flash('Paciente no encontrado')
        return redirect(url_for('dashboard'))
    
    patient_name = patients[patient_id]['name']
    
    if delete_patient(patient_id):
        write_log(f'/delete_patient/{patient_id}', f'OK - Paciente eliminado: {patient_name}', session['username'])
        flash(f'Paciente {patient_name} eliminado exitosamente')
    else:
        flash('Error al eliminar paciente')
    
    return redirect(url_for('dashboard'))

# Endpoint para generar QR
@app.route('/generate_qr')
def generate_qr():
    try:
        # Obtener la URL base de la aplicación
        base_url = request.url_root
        
        # Crear el código QR
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(base_url)
        qr.make(fit=True)
        
        # Crear imagen del QR
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convertir a base64 para mostrar en HTML
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        write_log('/generate_qr', 'OK - QR generado')
        return jsonify({
            "qr_code": f"data:image/png;base64,{img_str}",
            "url": base_url
        })
    except Exception as e:
        print(f"Error generando QR: {e}")
        return jsonify({"error": "Error generando código QR"}), 500

# Endpoint para ver logs via API
@app.route('/api/logs', methods=['GET'])
@validate_version
def api_logs():
    try:
        limit = request.args.get('limit', 100, type=int)
        log_lines = read_logs(limit=limit)
        
        logs = []
        for line in reversed(log_lines):
            parsed_log = parse_log_line(line)
            if parsed_log:
                logs.append(parsed_log)
        
        write_log('/api/logs', 'OK - Consulta de logs via API')
        return jsonify({"logs": logs}), 200
    except Exception as e:
        write_log('/api/logs', 'ERROR - No se pudieron leer los logs')
        return jsonify({"error": "No se pudieron leer los logs"}), 500

# Ruta de salud para verificar que la aplicación está funcionando
@app.route('/health')
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": SUPPORTED_VERSION
    }), 200

# Manejador de errores 404
@app.errorhandler(404)
def not_found(error):
    write_log(request.path, 'ERROR - 404 Not Found')
    if request.path.startswith('/api/'):
        return jsonify({"error": "Endpoint no encontrado"}), 404
    return render_template('404.html'), 404

# Manejador de errores 500
@app.errorhandler(500)
def internal_error(error):
    write_log(request.path, 'ERROR - 500 Internal Server Error')
    if request.path.startswith('/api/'):
        return jsonify({"error": "Error interno del servidor"}), 500
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
