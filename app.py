from flask import Flask, render_template, redirect, url_for, request, flash
from flask_mysqldb import MySQL
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

mysql = MySQL(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password


@login_manager.user_loader
def load_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    if user:
        return User(user[0], user[1], user[2])
    return None


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()
        if user and bcrypt.check_password_hash(user[2], password_input):
            login_user(User(user[0], user[1], user[2]))
            return redirect(url_for('dashboard'))
        flash('Credenciales inválidas')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password_input).decode('utf-8')
        cur = mysql.connection.cursor()
        try:
            cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
            mysql.connection.commit()
            flash('Registro exitoso, ahora puedes iniciar sesión')
            return redirect(url_for('login'))
        except:
            flash('El usuario ya existe')
        finally:
            cur.close()
    return render_template('register.html')


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    cur = mysql.connection.cursor()
    if request.method == 'POST':
        todo = request.form['todo']
        cur.execute("INSERT INTO todos (user_id, content) VALUES (%s, %s)", (current_user.id, todo))
        mysql.connection.commit()
    cur.execute("SELECT id, content FROM todos WHERE user_id = %s", (current_user.id,))
    todos = cur.fetchall()
    cur.close()
    return render_template('dashboard.html', todos=todos)


@app.route('/delete/<int:id>')
@login_required
def delete(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM todos WHERE id = %s AND user_id = %s", (id, current_user.id))
    mysql.connection.commit()
    cur.close()
    return redirect(url_for('dashboard'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
