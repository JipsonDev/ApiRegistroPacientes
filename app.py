from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import json
import os
from datetime import datetime
import uuid
import qrcode
import io
import base64

app = Flask(__name__)
app.secret_key = 'tu_clave_secreta_aqui'  # Cambia esto por una clave secreta segura

# Archivos de datos
USERS_FILE = 'usuarios.json'
PATIENTS_FILE = 'pacientes.json'
LOG_FILE = 'log.txt'

# Versión soportada
SUPPORTED_VERSION = '1.0'

# Inicializar archivos si no existen
def init_files():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'w') as f:
            json.dump({}, f)
    
    if not os.path.exists(PATIENTS_FILE):
        with open(PATIENTS_FILE, 'w') as f:
            json.dump({}, f)
    
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w') as f:
            f.write("=== LOG DE AUDITORÍA ===\n")

# Función para escribir en el log de auditoría
def write_log(ruta, resultado, usuario=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip = request.remote_addr
    user_info = f" | Usuario: {usuario}" if usuario else ""
    
    log_entry = f"[{timestamp}] IP: {ip} | Ruta: {ruta} | Resultado: {resultado}{user_info}\n"
    
    with open(LOG_FILE, 'a') as f:
        f.write(log_entry)

# Decorador para validar versión
def validate_version(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Buscar versión en JSON body
        version = None
        if request.is_json:
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

# Decorador para verificar login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            write_log(request.path, "ERROR - No autenticado")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Funciones para manejar usuarios
def load_users():
    try:
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def load_patients():
    try:
        with open(PATIENTS_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_patients(patients):
    with open(PATIENTS_FILE, 'w') as f:
        json.dump(patients, f, indent=2)

# Rutas principales
@app.route('/')
def index():
    write_log('/', 'OK')
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        users = load_users()
        
        if username in users and check_password_hash(users[username]['password'], password):
            session['user_id'] = username
            session['username'] = username
            write_log('/login', f'OK - Login exitoso', username)
            return redirect(url_for('dashboard'))
        else:
            write_log('/login', f'ERROR - Credenciales incorrectas para {username}')
            flash('Usuario o contraseña incorrectos')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        users = load_users()
        
        if username in users:
            write_log('/register', f'ERROR - Usuario ya existe: {username}')
            flash('El usuario ya existe')
        else:
            users[username] = {
                'password': generate_password_hash(password),
                'email': email,
                'created_at': datetime.now().isoformat()
            }
            save_users(users)
            write_log('/register', f'OK - Usuario registrado: {username}')
            flash('Usuario registrado exitosamente')
            return redirect(url_for('login'))
    
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

# API Endpoints para Postman
@app.route('/api/register', methods=['POST'])
@validate_version
def api_register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    
    if not all([username, password, email]):
        write_log('/api/register', 'ERROR - Datos incompletos')
        return jsonify({"error": "Faltan datos requeridos"}), 400
    
    users = load_users()
    
    if username in users:
        write_log('/api/register', f'ERROR - Usuario ya existe: {username}')
        return jsonify({"error": "El usuario ya existe"}), 409
    
    users[username] = {
        'password': generate_password_hash(password),
        'email': email,
        'created_at': datetime.now().isoformat()
    }
    save_users(users)
    
    write_log('/api/register', f'OK - Usuario registrado via API: {username}')
    return jsonify({"message": "Usuario registrado exitosamente"}), 201

@app.route('/api/login', methods=['POST'])
@validate_version
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not all([username, password]):
        write_log('/api/login', 'ERROR - Datos incompletos')
        return jsonify({"error": "Username y password requeridos"}), 400
    
    users = load_users()
    
    if username in users and check_password_hash(users[username]['password'], password):
        token = str(uuid.uuid4())  # Token simple para demo
        write_log('/api/login', f'OK - Login API exitoso', username)
        return jsonify({"message": "Login exitoso", "token": token}), 200
    else:
        write_log('/api/login', f'ERROR - Credenciales incorrectas API para {username}')
        return jsonify({"error": "Credenciales incorrectas"}), 401

@app.route('/api/patients', methods=['GET', 'POST'])
@validate_version
def api_patients():
    if request.method == 'GET':
        patients = load_patients()
        write_log('/api/patients', 'OK - Consulta de pacientes via API')
        return jsonify(patients), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        name = data.get('name')
        age = data.get('age')
        symptoms = data.get('symptoms')
        
        if not all([name, age, symptoms]):
            write_log('/api/patients', 'ERROR - Datos de paciente incompletos')
            return jsonify({"error": "Faltan datos del paciente"}), 400
        
        patients = load_patients()
        patient_id = str(uuid.uuid4())
        
        patients[patient_id] = {
            'name': name,
            'age': age,
            'symptoms': symptoms,
            'created_at': datetime.now().isoformat()
        }
        
        save_patients(patients)
        write_log('/api/patients', f'OK - Paciente registrado via API: {name}')
        return jsonify({"message": "Paciente registrado exitosamente", "patient_id": patient_id}), 201

@app.route('/api/patients/<patient_id>', methods=['GET', 'PUT', 'DELETE'])
@validate_version
def api_patient_operations(patient_id):
    patients = load_patients()
    
    if patient_id not in patients:
        write_log(f'/api/patients/{patient_id}', 'ERROR - Paciente no encontrado')
        return jsonify({"error": "Paciente no encontrado"}), 404
    
    if request.method == 'GET':
        write_log(f'/api/patients/{patient_id}', 'OK - Consulta de paciente específico')
        return jsonify(patients[patient_id]), 200
    
    elif request.method == 'PUT':
        data = request.get_json()
        name = data.get('name')
        age = data.get('age')
        symptoms = data.get('symptoms')
        
        if not all([name, age, symptoms]):
            write_log(f'/api/patients/{patient_id}', 'ERROR - Datos de actualización incompletos')
            return jsonify({"error": "Faltan datos del paciente"}), 400
        
        patients[patient_id].update({
            'name': name,
            'age': age,
            'symptoms': symptoms,
            'updated_at': datetime.now().isoformat()
        })
        
        save_patients(patients)
        write_log(f'/api/patients/{patient_id}', f'OK - Paciente actualizado via API: {name}')
        return jsonify({"message": "Paciente actualizado exitosamente"}), 200
    
    elif request.method == 'DELETE':
        patient_name = patients[patient_id]['name']
        del patients[patient_id]
        save_patients(patients)
        write_log(f'/api/patients/{patient_id}', f'OK - Paciente eliminado via API: {patient_name}')
        return jsonify({"message": "Paciente eliminado exitosamente"}), 200

# Ruta para agregar paciente desde el dashboard
@app.route('/add_patient', methods=['POST'])
@login_required
def add_patient():
    name = request.form['name']
    age = request.form['age']
    symptoms = request.form['symptoms']
    
    if not all([name, age, symptoms]):
        write_log('/add_patient', 'ERROR - Datos de paciente incompletos')
        flash('Todos los campos son requeridos')
        return redirect(url_for('dashboard'))
    
    patients = load_patients()
    patient_id = str(uuid.uuid4())
    
    patients[patient_id] = {
        'name': name,
        'age': age,
        'symptoms': symptoms,
        'created_at': datetime.now().isoformat(),
        'created_by': session['username']
    }
    
    save_patients(patients)
    write_log('/add_patient', f'OK - Paciente agregado: {name}', session['username'])
    flash('Paciente agregado exitosamente')
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
        name = request.form['name']
        age = request.form['age']
        symptoms = request.form['symptoms']
        
        if not all([name, age, symptoms]):
            write_log(f'/edit_patient/{patient_id}', 'ERROR - Datos de actualización incompletos')
            flash('Todos los campos son requeridos')
            return render_template('edit_patient.html', patient=patients[patient_id], patient_id=patient_id)
        
        patients[patient_id].update({
            'name': name,
            'age': age,
            'symptoms': symptoms,
            'updated_at': datetime.now().isoformat(),
            'updated_by': session['username']
        })
        
        save_patients(patients)
        write_log(f'/edit_patient/{patient_id}', f'OK - Paciente actualizado: {name}', session['username'])
        flash('Paciente actualizado exitosamente')
        return redirect(url_for('dashboard'))
    
    write_log(f'/edit_patient/{patient_id}', 'OK - Formulario de edición mostrado', session['username'])
    return render_template('edit_patient.html', patient=patients[patient_id], patient_id=patient_id)

# Ruta para eliminar paciente desde el dashboard
@app.route('/delete_patient/<patient_id>')
@login_required
def delete_patient(patient_id):
    patients = load_patients()
    
    if patient_id not in patients:
        write_log(f'/delete_patient/{patient_id}', 'ERROR - Paciente no encontrado')
        flash('Paciente no encontrado')
        return redirect(url_for('dashboard'))
    
    patient_name = patients[patient_id]['name']
    del patients[patient_id]
    save_patients(patients)
    
    write_log(f'/delete_patient/{patient_id}', f'OK - Paciente eliminado: {patient_name}', session['username'])
    flash(f'Paciente {patient_name} eliminado exitosamente')
    return redirect(url_for('dashboard'))

# Endpoint para generar QR
@app.route('/generate_qr')
def generate_qr():
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

# Endpoint para ver logs (solo para desarrollo)
@app.route('/api/logs', methods=['GET'])
@validate_version
def api_logs():
    try:
        with open(LOG_FILE, 'r') as f:
            logs = f.read()
        write_log('/api/logs', 'OK - Consulta de logs')
        return jsonify({"logs": logs}), 200
    except:
        write_log('/api/logs', 'ERROR - No se pudieron leer los logs')
        return jsonify({"error": "No se pudieron leer los logs"}), 500

if __name__ == '__main__':
    init_files()
    app.run(debug=True)
