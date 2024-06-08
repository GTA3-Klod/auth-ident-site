from flask import Flask, request, redirect, url_for, session, render_template, flash
from datetime import datetime, timedelta
import random

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # необхідно для сесій

# Клас для користувачів
class User:
    def __init__(self, username, password, access_level):
        self.username = username
        self.password = password
        self.access_level = access_level

# Операційний журнал
class OperationLog:
    def __init__(self):
        self.entries = []

    def log_action(self, username, action):
        self.entries.append({
            'timestamp': datetime.now(),
            'username': username,
            'action': action
        })

# Клас для управління реєстраційним журналом
class RegistrationLog:
    def __init__(self):
        self.users = [
            User("admin", "admin123", "admin"),
            User("user1", "password1", "user"),
            User("user2", "password2", "user")
        ]
        self.questions = [
            "What is your favorite color?",
            "What is your pet's name?",
            "What is your mother's maiden name?",
            "What was the name of your first school?",
            "What is your favorite food?",
            "What city were you born in?",
            "What is your favorite movie?",
            "What is your favorite book?",
            "What is your father's middle name?",
            "What is your favorite sport?",
            "What is your favorite hobby?",
            "What was your first car?",
            "What is your favorite animal?",
            "What is your favorite song?",
            "What is your favorite drink?"
        ]

    def login(self, username, password):
        for user in self.users:
            if user.username == username and user.password == password:
                return user
        return None

    def add_user(self, username, password, access_level):
        self.users.append(User(username, password, access_level))

    def delete_user(self, username):
        self.users = [user for user in self.users if user.username != username]

log = RegistrationLog()
operation_log = OperationLog()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = log.login(username, password)
    if user:
        session['username'] = user.username
        session['access_level'] = user.access_level
        session['last_auth'] = datetime.now()
        operation_log.log_action(user.username, "Logged in")
        if user.access_level == 'admin':
            return redirect(url_for('manage'))  # Перенаправлення на сторінку управління для адміністратора
        else:
            return redirect(url_for('user'))  # Перенаправлення на сторінку користувача
    else:
        #flash("Invalid username or password.")
        return redirect(url_for('reauth'))

@app.route('/manage')
def manage():
    if 'username' not in session or session.get('access_level') != 'admin':
        return redirect(url_for('index'))
    return render_template('manage.html', users=log.users, log=operation_log.entries)

from flask import redirect, url_for, session
from datetime import datetime, timedelta

@app.route('/user')
def user():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    last_auth = session.get('last_auth')
    if last_auth is None:
        # Якщо ключ 'last_auth' відсутній, перенаправити користувача на сторінку перевірки ідентифікації
        return redirect(url_for('reauth'))
    
    last_auth = last_auth.replace(tzinfo=None)  # Перетворюємо на offset-naive datetime
    if datetime.now() - last_auth > timedelta(minutes=5):
        # Перенаправити користувача на сторінку перевірки ідентифікації через таймаут
        return redirect(url_for('reauth'))
    
    # Передаємо список питань для аутентифікації до шаблону
    auth_questions = log.questions.copy()  # Копіюємо список, щоб не змінювати оригінал
    if 'auth_questions' in session:
        # Видаляємо вибрані користувачем питання з загального списку
        for question in session['auth_questions']:
            if question in auth_questions:
                auth_questions.remove(question)

    return render_template('user.html', questions=auth_questions)


@app.route('/set_auth_questions', methods=['POST'])
def set_auth_questions():
    if 'username' not in session:
        return redirect(url_for('index'))

    # Отримайте вибрані користувачем питання з форми
    question1 = request.form['question1']
    question2 = request.form['question2']
    question3 = request.form['question3']

    # Оновіть налаштування користувача в сесії
    session['auth_questions'] = [question1, question2, question3]

    # Видаліть вибрані питання з загального списку, щоб їх не можна було вибрати знову
    for question in [question1, question2, question3]:
        if question in log.questions:
            log.questions.remove(question)

    flash("Authentication questions saved successfully.")
    return redirect(url_for('user'))

@app.route('/reauth')
def reauth():
    if 'username' not in session:
        return redirect(url_for('index'))
    questions = random.sample(log.questions, 3)
    session['auth_questions'] = questions
    return render_template('reauth.html', questions=questions)

@app.route('/reauth', methods=['POST'])
def reauth_post():
    answers = request.form.getlist('answers')
    # тут буде логіка для перевірки відповідей, якщо вона є
    session['last_auth'] = datetime.now()
    flash("Reauthentication successful.")
    return redirect(url_for('user'))

@app.route('/logout')
def logout():
    username = session.get('username')
    session.pop('username', None)
    session.pop('access_level', None)
    session.pop('last_auth', None)
    if username:
        operation_log.log_action(username, "Logged out")
    return redirect(url_for('index'))

@app.route('/add_user', methods=['POST'])
def add_user():
    if 'username' not in session or session.get('access_level') != 'admin':
        return redirect(url_for('index'))
    username = request.form['username']
    password = request.form['password']
    access_level = request.form['access_level']
    log.add_user(username, password, access_level)
    operation_log.log_action(session['username'], f"Added user {username}")
    return redirect(url_for('manage'))

@app.route('/delete_user', methods=['POST'])
def delete_user():
    if 'username' not in session or session.get('access_level') != 'admin':
        return redirect(url_for('index'))
    username = request.form['username']
    log.delete_user(username)
    operation_log.log_action(session['username'], f"Deleted user {username}")
    return redirect(url_for('manage'))

if __name__ == '__main__':
    app.run(debug=True)
