import sqlite3
import calendar
import secrets
from datetime import date, datetime, timedelta
from flask import Flask, render_template, request, redirect, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import re
from markupsafe import escape
from functools import wraps
import uuid
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import os

api_key = os.getenv("API_KEY")
if api_key is None:
    raise ValueError("SECRET_KEY not set!")

app = Flask(__name__)
app.secret_key = api_key
csrf = CSRFProtect(app) # Enforces protection against CSRF

app.config.update(
    SESSION_COOKIE_SECURE=True,         # Enforce HTTPS
    SESSION_COOKIE_HTTPONLY=True,       # Prevents client-side JS
    SESSION_COOKIE_SAMESITE='Strict'    # Prevents CSRF attacks
)

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15) # User's session expires after 15 minutes

limiter = Limiter(get_remote_address, app=app, default_limits=["20 per minute"]) # Sets limit of 20 connections per route, per minute for each user

def init_db(): # Initialises the Database if it is absent 
    conn = sqlite3.connect('tutti.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('user','admin')),
                    class_id INTEGER NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (class_id) REFERENCES classes(id)
                    )
                   ''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS sessions(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    time INTEGER NOT NULL,
                    date TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                    )
                   ''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS tasks(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    desc TEXT NOT NULL,
                    due TEXT NOT NULL,
                    class_id INTEGER NOT NULL,
                    FOREIGN KEY (class_id) REFERENCES classes(id)
                    )
                   ''')
    cursor.execute('''
                    CREATE TABLE IF NOT EXISTS user_tasks(
                    user_id INTEGER,
                    task_id INTEGER,
                    completed INTEGER,
                    PRIMARY KEY (user_id, task_id),
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (task_id) REFERENCES tasks(id)
                    )
                    ''')
    cursor.execute('''
                    CREATE TABLE IF NOT EXISTS classes(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL
                    )
                    ''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS invite_codes(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code_hash TEXT NOT NULL,
                    class_id INTEGER NOT NULL,
                    uses_remaining INTEGER NOT NULL DEFAULT 1,
                    expires_at TEXT,
                    created_by INTEGER,
                    FOREIGN KEY (class_id) REFERENCES classes(id),
                    FOREIGN KEY (created_by) REFERENCES users(id)
                    )
                   ''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS actions_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    date TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                   )
                   ''')
    conn.commit()
    conn.close()

def is_valid_item(item):
    return (
        isinstance(item, str)
        and 0 < len(item.strip()) <= 255
        and re.fullmatch(r"[a-zA-Z0-9\s.,'!?:;()\/&-]+", item)
    ) # Checks all data run through here to see if it is a non-empty string, between 0 to 255 characters, and if it contains allowed characters

def comp_incomp_split(class_id): # Function to determine how many users have completed each task
    conn = sqlite3.connect('tutti.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tasks WHERE class_id = ?", (class_id,))
    tasks_raw = cursor.fetchall()
    tasks = []
    if not tasks_raw:
        tasks = "You have no assigned tasks!"
    else:
        for task in tasks_raw:
            task_items = []
            complete = 0
            incomplete = 0
            for item in task:
                task_items.append(item)
            task_id = task_items[0]
            cursor.execute("SELECT completed FROM user_tasks WHERE task_id = ?", (task_id,))
            users = cursor.fetchall()
            for user in users:
                if user[0] == 0:
                    incomplete += 1
                else:
                    complete += 1
            task_items.append(complete)
            task_items.append(incomplete)
            tasks.append(task_items)
    
    conn.commit()
    conn.close()
    return tasks

def check_permissions(r_role): # The decorator that checks the user is the correct role to access each route
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user_id = session.get('user_id')
            if not user_id:
                return redirect('/unauthorised')

            conn = sqlite3.connect('tutti.db')
            cursor = conn.cursor()
            cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            conn.close()

            if not row or row[0] != r_role:
                return redirect('/unauthorised')

            return f(*args, **kwargs)
        return wrapper
    return decorator

def delete_task(task_id, user_ids): # Deletes tasks (performs this differently based in idv or all class action)
    
    conn = sqlite3.connect('tutti.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
    task = cursor.fetchone() # Collect a record of the task were about to delete (can't let it be gone forever!)

    user_id = session.get('user_id')
    cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    agent = cursor.fetchone() # Who dunnit?

    if user_ids == "all": # This deletes the task for all the users
        cursor.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
        cursor.execute("DELETE FROM user_tasks WHERE task_id = ?", (task_id,)) 
        rec = f"{agent} DELETED {task} from tasks and user_tasks"
    else: # and this deletes it for just one
        cursor.execute("DELETE FROM user_tasks WHERE task_id = ? AND user_id = ?", (task_id, user_ids,)) 
        rec = f"{agent} DELETED {task} from user_tasks for user {user_ids}"

    dt = date.today()
    cursor.execute("INSERT INTO actions_log (user_id, action, date) VALUES (?, ?, ?)", (user_id, rec, dt,)) # Makes record of action
    # "I'll be with you. Even if you can't see me"

    conn.commit()
    conn.close()
    return

def load_teacher_main():
    conn = sqlite3.connect('tutti.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username, class_id FROM users WHERE username = ?", (session['username'],)) 
    row = cursor.fetchone()
    username = row[0]
    class_id = row[1]
    # Collect the info on everyone in the class (except the current user)
    cursor.execute("SELECT username, id, role FROM users WHERE class_id = ? AND username != ?", (class_id, username,))
    student_users = cursor.fetchall()
    students = []
    # Have to do this for each user in the class
    for student in student_users:
        username = student[0]
        user_id = student[1]
        role = student[2]
        cursor.execute("SELECT id FROM sessions WHERE user_id = ?", (user_id,))
        sessions = cursor.fetchall()
        sess_num = len(sessions)
        cursor.execute("SELECT task_id, completed FROM user_tasks WHERE user_id = ?", (user_id,))
        tasks = cursor.fetchall()
        past = 0
        future = 0
        # For each task, we need to check if it's been completed (and if not, if it's overdue, or due later)
        for task in tasks:
            task_id = task[0]
            cursor.execute("SELECT due FROM tasks WHERE id = ?", (task_id,))
            curr_task = cursor.fetchone()
            if task[1] == 0:
                today = date.today()
                format_string = "%Y-%m-%d"
                dt_obj1 = datetime.strptime(curr_task[0], format_string)
                if dt_obj1.date() < today:
                    past +=1
                else:
                    future += 1

        students.append([user_id, username, sess_num, past, future, role])
    conn.commit()
    conn.close()
    return students

init_db()

@app.before_request
def make_session_permanent(): # Tells flask that it should enforce the session lifetime of each user
    session.permanent = True

# Below are a couple routes made to handle unauthorised requests, or handle errors

@app.route('/unauthorised')
def unauthorised():
    return render_template('unauthorised.html')

@app.errorhandler(400)
def bad_request_error(error):
    return render_template('error.html', message="Bad Request: Please check your input."), 400

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('error.html', message="Forbidden: You don’t have permission to access this."), 403

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', message="Page Not Found: The resource you requested does not exist."), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', message="Internal Server Error: Something went wrong on our end."), 500

@app.route('/')
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute") # Limits the amount of requests each user can make to the login route specifically to 5 per minute
def login():
    user_id = session.get('user_id') # Uses sessions to authenticate the correct user each time
    if user_id: # Without a session, they are redirected to logout
        return redirect('/logout')
    else:
        if request.method == "POST":
            try:
                username = request.form['username'] # Uses POST to ensure extra layer of privacy
                password = request.form["password"]
                session['csrf_token'] = str(uuid.uuid4())  # Add a CSRF token to mitigate session fixation atttacks
                safe_usrnm = escape(username) # Escapes value to prevent XSS attacks
                conn = sqlite3.connect("tutti.db")
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE username = ?", (safe_usrnm,))
                user = cursor.fetchone()
                conn.commit()
                conn.close()
                if user and check_password_hash(user[2], password): # Checks the password against the hash
                    session["user_id"] = user[0]
                    session["username"] = user[1]
                    flash("Login successful!", "success")
                    if user[3] == 'admin':
                        return redirect("/teacher_main")
                    else:
                        return redirect("/student_main")
                flash("Invalid username or password.", "error")
            except sqlite3.IntegrityError:
                flash('A database integrity error occurred. Please try again.', 'error')
            except sqlite3.Error:
                flash('A database error occurred. Please contact support.', 'error')

    return render_template("login.html")

@app.route('/register_student', methods=["GET", 'POST'])
def register_student():
    user_id = session.get('user_id')
    if user_id:
        return redirect('/logout')  # Redirect logged-in users

    if request.method == "POST":
        try:
            username = escape(request.form.get("username", "").strip())
            password = request.form.get("password", "")
            password_con = escape(request.form.get("password_con", "").strip())
            invite_code = escape(request.form.get("invite_code", "").strip())  # Escapes input to prevent XSS

            if not is_valid_item(username):
                flash('Invalid username. Please enter a valid username.', 'error')
            elif not is_valid_item(password_con):
                flash('Invalid password. Please enter a valid password.', 'error')  # Ensures inputs are safe length
            elif password != password_con:
                flash("Passwords don't match", "error")
            else:
                password_hash = generate_password_hash(
                    password,
                    method="pbkdf2:sha256",
                    salt_length=16
                )  # Stored hashed to prevent password leaks

                conn = sqlite3.connect("tutti.db")
                cursor = conn.cursor()

                cursor.execute("SELECT id, code_hash, class_id, uses_remaining, expires_at FROM invite_codes")
                invites = cursor.fetchall()

                invite = None
                for i in invites:
                    # Check invite code using hash comparison
                    if check_password_hash(i[1], invite_code):
                        invite = i
                        break

                if not invite:
                    flash("Invalid invite code", "error")  # Not in database
                elif invite[3] <= 0:
                    flash("Invite code already used", "error")  # No remaining uses
                elif invite[4] and datetime.fromisoformat(invite[4]) < datetime.utcnow():
                    flash("Invite code has expired", "error")  # Expired
                else:
                    cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
                    if cursor.fetchone():
                        flash("Username already exists", "error")
                    else:
                        cursor.execute(
                            "INSERT INTO users (username, password_hash, role, class_id) VALUES (?, ?, 'user', ?)",
                            (username, password_hash, invite[2])
                        )

                        cursor.execute(
                            "UPDATE invite_codes SET uses_remaining = uses_remaining - 1 WHERE id = ?",
                            (invite[0],)
                        ) # Ensure that the code is set in the database as already being used (this ensures that once a student has used a code, no one else can use it to hack into the system)

                        conn.commit()
                        conn.close()
                        flash("Account created successfully!", "success")
                        return redirect("/login")

        except sqlite3.IntegrityError:
            flash('A database integrity error occurred. Please try again.', 'error')
        except sqlite3.Error:
            flash('A database error occurred. Please contact support.', 'error')

    return render_template("register_student.html")

@app.route('/create_class', methods=["GET", 'POST'])
def create_class():
    user_id = session.get('user_id')
    if user_id:
        return redirect('/logout')
    else:
        try:
            if request.method == "POST":
                username = request.form["username"]
                password = request.form["password"]
                password_con = request.form["password_con"]
                classname = request.form["classname"]

                safe_usrnm = escape(username)
                safe_clssnm = escape(classname) # Escapes each input to prevent XSS attacks

                if not is_valid_item(safe_usrnm):
                    flash('Invalid username. Please enter a valid username.', 'error')

                elif not is_valid_item(safe_clssnm):
                    flash('Invalid classname. Please enter a valid classname.', 'error') # Checks each input is a valid input (e.g. between 0 to 255 characters)
                
                elif password != password_con:
                    flash("Passwords don't match", "error")
                
                else:
                    password_hash = generate_password_hash(
                        password,
                        method="pbkdf2:sha256",
                        salt_length=16
                    ) # Hashes password so that it stored encrypted to prevent intruders in the database from gathering passwords

                    conn = sqlite3.connect("tutti.db")
                    cursor = conn.cursor()

                    cursor.execute("SELECT 1 FROM users WHERE username = ?", (safe_usrnm,))

                    if cursor.fetchone(): # Checks if the username already exists in the database
                        flash("Username already exists", "error")
                    else:
                        cursor.execute("""INSERT INTO classes (name) VALUES (?)""", 
                                (safe_clssnm,))
                        class_id = cursor.lastrowid # Creates the class and collects it's ID from the database

                        cursor.execute("""INSERT INTO users (username, password_hash, role, class_id) VALUES (?, ?, 'admin', ?)""", 
                                    (safe_usrnm, password_hash, class_id,))
                        
                        flash("Registration successful. Please log in.", "success")
                        conn.commit()
                        conn.close()
                        return redirect("/login")
        except sqlite3.IntegrityError: # Two exceptions to catch any SQL errors
            flash('A database integrity error occurred. Please try again.', 'error')
        except sqlite3.Error:
            flash('A database error occurred. Please contact support.', 'error')

        return render_template("create_class.html")

@app.route("/student_main", methods=["GET", "POST"])
@app.route("/student_main/<int:year>/<int:month_num>/", methods=["GET", "POST"])
@check_permissions("user") # Decorator ensures only student's access the the student page
def student_main(year=None, month_num=None):
    conn = sqlite3.connect('tutti.db')
    cursor = conn.cursor()

    dt = date.today()
    if (year is None or month_num is None) or (year==dt.year and month_num == dt.month) : # Check whether the route recieved any year/month data from the url
        year = dt.year
        month_num = int(dt.month)
        curr_day = int(dt.strftime("%d"))
        month_str = dt.strftime("%B")
    else:
        temp_dt = date(year, month_num, 1)
        curr_day = None
        month_str = temp_dt.strftime("%B")

    # A little bit of organising to manage moving between years

    prev_month = month_num - 1
    prev_year = year
    if prev_month == 0:
        prev_month = 12
        prev_year -= 1

    next_month = month_num + 1
    next_year = year
    if next_month == 13:
        next_month = 1
        next_year += 1

    # Generate the calendar and store it in a list so HTML can render it more easily

    cale = calendar.monthcalendar(year, month_num)
    current_month = []
    for week in cale:
        current_month.append(week)

    # Collects the user ID from the session to ensure the correct data is rendered

    cursor.execute("SELECT username, id FROM users WHERE username = ?", (session['username'],))
    row = cursor.fetchone()
    username = row[0]
    user_id = row[1]

    # Identify what tasks have not been completed by the user so they may be listed

    cursor.execute("SELECT task_id FROM user_tasks WHERE user_id = ? AND completed = 0", (user_id,))
    task_ids = cursor.fetchall()
    tasks = []
    if not task_ids:
        tasks = "You have no tasks to complete!"
        pasttasks = []
        futtasks = []
    else:
        for row in task_ids:
            cursor.execute("SELECT * FROM tasks WHERE id = ?", (row[0],))
            tup = cursor.fetchone()
            task = list(tup)
            tasks.append(task)
        tasks = sorted(tasks, key=lambda x: x[3]) # Sort by their due date so that the oldest are at the top

        pasttasks = []
        futtasks = []

        # A little more logic to figure out what tasks are due before and after the current date

        for i in tasks:
            y, m, d = map(int, i[3].split("-"))
            task_date = date(y, m, d)
            if year == y and month_num == m:
                if task_date < dt:
                    pasttasks.append(int(task_date.strftime("%d")))
                else:
                    futtasks.append(int(task_date.strftime("%d")))
    conn.commit()
    conn.close()

    return render_template("student_main.html", 
                           username=username, 
                           month=month_str, 
                           curr_day=curr_day, 
                           current_month=current_month,
                           year=year,
                           prev_year=prev_year,
                           prev_month=prev_month,
                           next_year=next_year,
                           next_month=next_month,
                           tasks=tasks,
                           pasttasks=pasttasks,
                           futtasks=futtasks) # Send EVERYTHING to the HTML

@app.route('/teacher_main', methods=["GET", "POST"])
@check_permissions("admin") # Ensure only admins can access this page (IMPORTANT! as this is where you manage users and tasks)
def teacher_main():
    students = load_teacher_main()
    return render_template("teacher_main.html", students=students)

@app.route('/create_task', methods=["POST"])
@check_permissions("admin") # Again, only admins should be able to do this
def create_task():
    name = request.form.get('name')
    desc = request.form.get("desc")
    due = request.form.get("due-date")
    # Collect name, description, and due date from client side

    safe_nm = escape(name)
    safe_dsc = escape(desc) # Escape values, and then ensure they are valid so that they cannot impact the system/database
    if not is_valid_item(safe_nm):
        flash('Invalid username. Please enter a valid name.', 'error')
    
    elif not is_valid_item(safe_dsc):
        flash('Invalid username. Please enter a valid description.', 'error')
    
    else:
        conn = sqlite3.connect('tutti.db')
        cursor = conn.cursor()
        cursor.execute("SELECT class_id FROM users WHERE username = ?", (session['username'],))
        row = cursor.fetchone()
        class_id = row[0]
        # Insert into the tasks table the values...
        cursor.execute("INSERT INTO tasks (name, desc, due, class_id) VALUES (?, ?, ?,?)", (safe_nm, safe_dsc, due, class_id))
        task_id = cursor.lastrowid
        cursor.execute("SELECT id FROM users WHERE class_id = ? AND username != ? AND role != 'admin'", (class_id, session['username']))
        student_ids = cursor.fetchall()
        # and then add them to the user_tasks table per student so that each student is assigned the task
        for student in student_ids:
            cursor.execute("INSERT INTO user_tasks (user_id, task_id, completed) VALUES (?, ?, ?)", (student[0], task_id, 0,))
        conn.commit()
        conn.close()

    return redirect("/teacher_tasks")

@app.route('/create_idv_task', methods=["GET", "POST"]) # This route is similar to the create_task, but only targets a specifc student
@check_permissions("admin")
def create_idv_task():
    name = request.form['name']
    desc = request.form["desc"]
    due = request.form["due-date"]
    student_id = request.form["student_id"]

    #As usual, escape and validate all inputs 
    safe_nm = escape(name)
    safe_dsc = escape(desc)
    if not is_valid_item(safe_nm):
        flash('Invalid username. Please enter a valid name.', 'error')
    
    elif not is_valid_item(safe_dsc):
        flash('Invalid username. Please enter a valid description.', 'error')
    
    else:
        conn = sqlite3.connect('tutti.db')
        cursor = conn.cursor()
        cursor.execute("SELECT class_id FROM users WHERE username = ?", (session['username'],))
        row = cursor.fetchone()
        class_id = row[0]
        # Insert into tasks table all values...
        cursor.execute("INSERT INTO tasks (name, desc, due, class_id) VALUES (?, ?, ?,?)", (safe_nm, safe_dsc, due, class_id))
        task_id = cursor.lastrowid
        # and then add task into user_tasks (but just for the one user)
        cursor.execute("INSERT INTO user_tasks (user_id, task_id, completed) VALUES (?, ?, ?)", (student_id, task_id, 0,))
        conn.commit()
        conn.close()

    session['student_id'] = student_id
    return redirect('/teacher_student')

@app.route('/teacher_tasks')
@check_permissions("admin")
def teacher_tasks():
    conn = sqlite3.connect('tutti.db')
    cursor = conn.cursor()
    user_id = session["user_id"]
    cursor.execute("SELECT class_id FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    class_id = row[0]
    conn.commit()
    conn.close()
    
    tasks = comp_incomp_split(class_id) # Sends the class ID to the comp_incom_split which sorts out a list with the complete/incomplete split of tasks

    return render_template('teacher_tasks.html', tasks=tasks)

@app.route('/teacher_student', methods=["GET", "POST"])
@check_permissions("admin")
def teacher_student():
    student_id = request.form.get("student_id") # This gets the student ID if it was sent from the main page
    if not student_id:
        student_id = session.get('student_id') # And if it was accessed another way, it collects it from the session

    try:
        conn = sqlite3.connect('tutti.db')
        cursor = conn.cursor()

        user_id = student_id
        cursor.execute("SELECT username, role FROM users WHERE id = ?", (student_id,))
        stats = cursor.fetchone()
        name = stats[0]
        role = stats[1]
        cursor.execute("SELECT id FROM sessions WHERE user_id = ?", (student_id,))
        sessions = cursor.fetchall()
        sess_num = len(sessions)
        cursor.execute("SELECT task_id, completed FROM user_tasks WHERE user_id = ?", (student_id,))
        task_ids = cursor.fetchall()
        past = 0
        future = 0
        # Identify for each task whether it is incompleted, and if so, whether it is overdue or due later
        for task in task_ids:
            task_id = task[0]
            cursor.execute("SELECT due FROM tasks WHERE id = ?", (task_id,))
            curr_task = cursor.fetchone()
            if task[1] == 0:
                today = date.today()
                format_string = "%Y-%m-%d"
                dt_obj1 = datetime.strptime(curr_task[0], format_string)
                if dt_obj1.date() < today:
                    past +=1
                else:
                    future += 1
        student = [user_id, name, sess_num, past, future]
        # Now append all tasks to a list to send to the client side
        tasks = []
        if not task_ids:
            tasks = "You have assigned no tasks to complete!"
        else:
            for row in task_ids:
                cursor.execute("SELECT * FROM tasks WHERE id = ?", (row[0],))
                tup = cursor.fetchone()
                task = list(tup)
                task.append(row[1])
                tasks.append(task)
            tasks = sorted(tasks, key=lambda x: x[3]) # Order by their due date
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError: # Raise an exception if a SQL error occurs
                flash('A database integrity error occurred. Please try again.', 'error')
    except sqlite3.Error:
        flash('A database error occurred. Please contact support.', 'error')
    
    return render_template('teacher_student.html', student=student, tasks=tasks, role=role)

@app.route('/teacher_stats')
@check_permissions("admin")
def teacher_stats():
    conn = sqlite3.connect('tutti.db')
    cursor = conn.cursor()

    # Gather the current users ID from the session and find their class ID
    user_id = session.get('user_id')
    cursor.execute("SELECT class_id FROM users WHERE id = ?", (user_id,))
    class_id = cursor.fetchone()
    class_id = class_id[0]

    # Create a 2D list that collects the total amount of session time from each student so that the JS can turn it into a graph
    cursor.execute("SELECT id FROM users WHERE class_id = ? AND id != ?", (class_id, user_id,))
    sessions = []
    sessions.append(["User", "Time"])
    users_raw = cursor.fetchall()
    if not users_raw:
        sessions = "You have no students yet!" # If there are no other users in the class, just send a string
    else:
        for user in users_raw:
            user = user[0]
            cursor.execute("SELECT time FROM sessions WHERE user_id = ?", (user,)) 
            times_raw = cursor.fetchall()
            total_time = 0
            for time in times_raw:
                total_time += time[0] # Add all the session times together 
            cursor.execute("SELECT username FROM users WHERE id = ?", (user,))
            name = cursor.fetchone()
            user_list = [name[0], total_time] # Append to the list the username and the total time
            sessions.append(user_list)

    conn.commit()
    conn.close()
    
    tasks = comp_incomp_split(class_id) # This gathers the complete/incomplete split per task
    if isinstance(tasks, list): # Check it is list (will return a string if no tasks)
        for task in tasks: # Then pop all the values we don't need so that only the name, complete count, and incomplete count are left
            task.pop(0)
            task.pop(1)
            task.pop(1)
            task.pop(1)
        tasks.insert(0, ["Task", "Complete", "Incomplete"]) # Add some headings... ready to send!

    return render_template('teacher_stats.html', sessions=sessions, tasks=tasks)

@app.route('/end_session', methods=["POST"])
@check_permissions("user")
def end_session():
    time = float(request.form.get('time'))
    dt = date.today()
    task_id = request.form.get("task_id")

    conn = sqlite3.connect('tutti.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (session['username'],))
    row = cursor.fetchone()
    user_id = row[0]
    if not task_id: # A little catch incase the client side sends us no ID
        task_id = None 
    else:
        task_id = int(task_id)
        cursor.execute('UPDATE user_tasks SET completed = 1 WHERE task_id = ? AND user_id = ?', 
                        (task_id, user_id)) # Set the task to be completed in it's instance in user_tasks
        cursor.execute("INSERT INTO sessions (time, date, user_id) VALUES (?, ?, ?)", (time, dt, user_id)) 
        # Add the session data to the session table for future use
    conn.commit()
    conn.close()
    return redirect('/student_main')

@app.route('/mark_complete', methods=["POST"]) # Pretty similar to the end_session route, with a few changes (the user hasn't actually competed the task, so there's no data on it!)
@check_permissions("admin")
def mark_complete():
    student_id = request.form['student_id']
    time = float(request.form['time'])
    dt = date.today()
    task_id = request.form["task_id"]

    conn = sqlite3.connect('tutti.db')
    cursor = conn.cursor()
    task_id = int(task_id)
    cursor.execute("SELECT completed FROM user_tasks WHERE task_id = ? and user_id = ?", (task_id, student_id,))
    locate = cursor.fetchone()
    if locate[0] == 0: # Check if the task has already been completed or not (can't complete a task twice!)
        cursor.execute('UPDATE user_tasks SET completed = 1 WHERE task_id = ? AND user_id = ?', 
                    (task_id, student_id)) # Update the user_tasks to say this task is complete
    conn.commit()
    conn.close()

    session['student_id'] = student_id
    return redirect('/teacher_student')

@app.route("/edit_item", methods=["POST"]) # Basically just sends through the edit_index to the client side so that the inputs appear
@check_permissions("admin")
def edit_item():
    edit_id = int(request.form.get("edit"))
    conn = sqlite3.connect('tutti.db')
    cursor = conn.cursor()
    user_id = session["user_id"]
    cursor.execute("SELECT class_id FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    class_id = row[0]
    conn.commit()
    conn.close()
    
    tasks = comp_incomp_split(class_id) # Get the function to send us back the complete/incomplete split on the class data
    return render_template("teacher_tasks.html", tasks=tasks, edit_index=edit_id)

@app.route("/save_item", methods=["POST"])
@check_permissions("admin")
def save_item():
    item_id = request.form.get("edit_index")
    new_name = request.form.get("name")
    new_desc = request.form.get("desc")
    new_due = request.form.get("new_due")

    # You know the drill folks, escape and validate!
    safe_nm = escape(new_name)
    safe_desc = escape(new_desc)
    safe_due = escape(new_due)
    if not is_valid_item(safe_nm):
        flash('Invalid username. Please enter a valid username.', 'error')
    elif not is_valid_item(safe_desc):
        flash('Invalid username. Please enter a valid username.', 'error')
    elif not is_valid_item(safe_due):
        flash('Invalid username. Please enter a valid username.', 'error')
    else:
        conn = sqlite3.connect('tutti.db')
        cursor = conn.cursor()
        cursor.execute('SELECT name, desc, due FROM tasks WHERE id = ?', 
                        (item_id,))
        og_task = cursor.fetchone() # Create a record of what the task was like previously

        cursor.execute('UPDATE tasks SET name = ?, desc = ?, due = ? WHERE id = ?', 
                    (safe_nm, safe_desc, safe_due, item_id)) # Update the instance in the tasks table with the new values

        user_id = session.get('user_id')
        cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
        agent = cursor.fetchone() # Collect the info on who performed this action

        rec = f"{agent} CHANGED {og_task} to {safe_nm, safe_desc, safe_due} in TASKS"
        dt = date.today()
        cursor.execute("INSERT INTO actions_log (user_id, action, date) VALUES (?, ?, ?)", (user_id, rec, dt,))
        # Make a record of what happend (It's a suprise tool that will help us later!)

        conn.commit()
        conn.close()
    return redirect("/teacher_tasks")

@app.route("/delete_item", methods=["POST"])
@check_permissions("admin")
def delete_item():
    item_id = request.form.get('delete')
    delete_task(item_id, "all")
    return redirect("/teacher_tasks")

@app.route("/delete_idv", methods=["GET", "POST"])
@check_permissions("admin")
def delete_idv():
    item_id = request.form.get('delete')
    student_id = request.form.get('student_id')
    delete_task(item_id, student_id)

    session['student_id'] = student_id
    return redirect("/teacher_student")

@app.route("/edit_student", methods=["POST"]) # Quite similar to the main page, but we need to send through the edit index as well (as well as a few other differences)
@check_permissions("admin")
def edit_student():
    edit_id = int(request.form.get("edit"))

    students = load_teacher_main()
    return render_template("teacher_main.html", students=students, edit_index=edit_id)

@app.route("/save_student", methods=["POST"])
@check_permissions("admin")
def save_student():
    user_id = request.form.get("edit_index")
    new_name = request.form.get("name")

    # WASH. YOUR. HANDS.
    safe_usrnm = escape(new_name)
    if not is_valid_item(safe_usrnm): 
        flash('Invalid username. Please enter a valid username.', 'error')
    else:
        conn = sqlite3.connect('tutti.db')
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users WHERE id = ?', 
                        (user_id,))
        usernm = cursor.fetchone() # Ensure we have a record of the old username
        cursor.execute('UPDATE users SET username = ? WHERE id = ?', 
                (safe_usrnm, user_id)) # Update the user's name

        user_id = session.get('user_id')
        cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
        agent = cursor.fetchone() # Find out who is making the edit
        rec = f"{agent} CHANGED {usernm[0]} to {safe_usrnm} in USERS"
        dt = date.today()
        cursor.execute("INSERT INTO actions_log (user_id, action, date) VALUES (?, ?, ?)", (user_id, rec, dt,))
        # Create the record of actions

        conn.commit()
        conn.close() 
    return redirect("/teacher_main")

@app.route("/delete_student", methods=["POST"])
@check_permissions("admin")
def delete_student():
    user_id = request.form.get('delete')
    conn = sqlite3.connect('tutti.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone() # Who are we deleting
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    cursor.execute("DELETE FROM user_tasks WHERE user_id = ?", (user_id,)) # "All those moments will be lost in time, like tears in rain"
    user_id = session.get('user_id')
    cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    agent = cursor.fetchone() # Who is deleting
    rec = f"{agent} DELETED {user} from users and user_tasks"
    dt = date.today() # When we deleted it
    cursor.execute("INSERT INTO actions_log (user_id, action, date) VALUES (?, ?, ?)", (user_id, rec, dt,))
    conn.commit()
    conn.close()
    return redirect("/teacher_main")

@app.route("/create_invite", methods=["POST"])
@check_permissions("admin")
def create_invite():
    conn = sqlite3.connect("tutti.db")
    cursor = conn.cursor()

    user_id = session["user_id"]
    cursor.execute("SELECT class_id FROM users WHERE id = ?", (user_id,))
    class_id = cursor.fetchone()[0]

    raw_code = secrets.token_urlsafe(8) # Create the class code
    code_hash = generate_password_hash(raw_code) # Store it hashed in the database for extra security

    expires_at = (datetime.utcnow() + timedelta(days=7)).isoformat() # Make an expiry date (ensures that if the student doesn't use it, it's unlikely that someone who may stumble upon it can use it)

    cursor.execute("""INSERT INTO invite_codes (code_hash, class_id, uses_remaining, expires_at, created_by) VALUES (?, ?, ?, ?, ?)""", 
                   (code_hash, class_id, 1, expires_at, user_id)) # A record of the code 

    conn.commit()
    conn.close()

    return jsonify({'code': raw_code}) # Send it back to the client side for JS to deal with

@app.route("/make_admin", methods=["POST"])
@check_permissions("admin")
def make_admin():
    student_id = request.form["student_id"]

    conn = sqlite3.connect('tutti.db')
    cursor = conn.cursor()
    # Update the users role to be an admin
    cursor.execute("UPDATE users SET role = ? WHERE id = ?", ("admin", student_id,)) # "You've always had the power, my dear, you just had to learn it for yourself."

    user_id = session.get('user_id')
    cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    agent = cursor.fetchone() # Record who gave them this power
    cursor.execute("SELECT id, username FROM users WHERE id = ?", (student_id,))
    alt_user = cursor.fetchone() # Record of who is getting this privledge
    rec = f"{agent} made {alt_user} ADMIN in USERS"
    dt = date.today()
    cursor.execute("INSERT INTO actions_log (user_id, action, date) VALUES (?, ?, ?)", (user_id, rec, dt,)) 
    # Store this record (keep this in mind, this secrect tool might help you later!)
    conn.commit()
    conn.close()

    session['student_id'] = student_id
    return redirect('/teacher_student')

@app.route("/revoke_admin", methods=["POST"])
@check_permissions("admin")
def revoke_admin():
    student_id = request.form["student_id"]

    conn = sqlite3.connect('tutti.db')
    cursor = conn.cursor()
    # Change the users role to user
    cursor.execute("UPDATE users SET role = ? WHERE id = ?", ("user", student_id,)) # "If you strike me down, I shall become more powerful than you could possibly imagine".

    user_id = session.get('user_id')
    cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    agent = cursor.fetchone() # And for the last time, Who did it...
    cursor.execute("SELECT id, username FROM users WHERE id = ?", (student_id,))
    alt_user = cursor.fetchone() # Who it's getting done to...
    rec = f"{agent} made {alt_user} USER in USERS"
    dt = date.today() # and when it happend
    cursor.execute("INSERT INTO actions_log (user_id, action, date) VALUES (?, ?, ?)", (user_id, rec, dt,)) # And store! This database is getting a workout
    conn.commit()
    conn.close()

    session['student_id'] = student_id
    return redirect('/teacher_student')

@app.route('/logout', methods=["POST", "GET"])
def logout():
    session.clear() # Clear the session, so the user can't use their previous session to access pages
    flash("You have been logged out.", "success")
    return redirect('/') # "E.T. phone home."

if __name__ == '__main__':
    app.run() # And.... ENGAGE!