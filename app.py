import sqlite3, os, subprocess, flask_login
from datetime import datetime
from flask import Flask, render_template, session, escape, request, Response, redirect, url_for, session, flash
from flask_login import current_user, login_user, logout_user
from flask_wtf import FlaskForm
from functools import wraps
from prettytable import PrettyTable
from sqlite3 import Error
from string import Template
from wtforms import TextAreaField, StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = '|3]Ds=Ns+hS9:QG~}QQx>Yx.GhZzM9'
database = 'sqlite_database.db'

# FORMS
class RegistrationForm(FlaskForm):
	username = StringField('Username', id='uname', validators=[
	                       DataRequired(), Length(min=3, max=15)])
	password = PasswordField('Password', id='pword', validators=[DataRequired()])
	tfa = StringField('tfa', id='2fa', validators=[Length(max=11)])
	submit = SubmitField('Register')

class LoginForm(FlaskForm):
	username = StringField('Username', id='uname', validators=[
	                       DataRequired(), Length(min=3, max=15)])
	password = PasswordField('Password', id='pword', validators=[DataRequired()])
	tfa = StringField('tfa', id='2fa', validators=[Length(max=11)])
	submit = SubmitField('Sign in')

class HistoryForm(FlaskForm):
    userquery = StringField('Username', id='userquery,')
    submit = SubmitField('Submit')

class SpellcheckForm(FlaskForm):
	text = StringField('Input text', id='inputtext', validators=[DataRequired()])
	submit = SubmitField('Submit')

class LoginHistory(FlaskForm):
	userid = StringField('', id='userid', validators=[DataRequired(), Length(min=3,max=15)])
	submit = SubmitField('Submit')

#******************************************************************************#
#******************************************************************************#
#******************************************************************************#

# DATABASE

# create connection to db
def sql_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        print(sqlite3.version)
        return conn
    except Error as e:
        print(e)
    return conn

def create_table(conn, create_table_sql):
    try:
        cr = conn.cursor()
        cr.execute(create_table_sql)
    except Error as e:
        print(e)
        
def create_users(conn, users):
    sql = "INSERT INTO users(name, password, tfa) VALUES(?,?,?)"
    cr = conn.cursor()
    cr.execute(sql, users)
    return cr.lastrowid

def create_admin(conn):
    sql = " INSERT INTO users(name, password, tfa) VALUES(?, ?, ?) "
    cr = conn.cursor()
    hash_pw = generate_password_hash("Administrator@1")
    user = ("admin", hash_pw, "12345678901")
    cr.execute(sql, user)
    return cr.lastrowid

def check_users(conn, user):
    try:
        cr = conn.cursor()
        cr.execute("SELECT name FROM users WHERE name = ?", (user,))
        data = cr.fetchone()
        if data is None:
            return True
        elif user == data[0]:
            return False
        else:
            return True
    except Error as e:
        print(e)
        
def store_text(conn, user, text, result):
    sql = "INSERT INTO text(user, submitted_text, result_text) VALUES(?, ?, ?)"
    cr = conn.cursor()
    cr.execute(sql, (user, text, result))
    return cr.lastrowid

# log user in and log user out time
def log_time(conn, log, user):
    print(log)
    if log == 'login':
        cr = conn.cursor()
        cr.execute("SELECT * FROM timestamp WHERE user = ? AND logout_time = 'N/A'", (user,))
        data = cr.fetchall()
        if len(data) is not 0:
            return 'User is already logged in'
        else:
            cr.execute("INSERT INTO timestamp(user, login_time, logout_time) values (?,?,?)", (user, datetime.now(), "N/A"))
        return cr.lastrowid
    if log == 'logout': # logout
        cr = conn.cursor()
        cr.execute("SELECT * FROM timestamp WHERE user = ? AND logout_time = 'N/A'", (user,))
        data = cr.fetchone()
        if data[3] == 'N/A':
            print('found')
            time = datetime.now()
            cr.execute("UPDATE timestamp SET logout_time = ? WHERE logout_time = 'N/A' AND user = ?", (time, user,))

# retireve histroy
def retrieve_queries(conn, user):
    cr = conn.cursor()
    cr.execute("SELECT id FROM text WHERE user = ?", (user,))
    data = cr.fetchall()
    return [elem[0] for elem in data]


def make_link(val):
    hrefVal = "/history/query" + str(val)
    return '<a href="' + hrefVal + '">' + str(val) + '</a>'

#******************************************************************************#
#******************************************************************************#
#******************************************************************************#

# ROUTES

@app.before_request
def before_request():
    if not os.path.exists(database):
        sql_create_users_table = """ CREATE TABLE IF NOT EXISTS users (
                                        id integer PRIMARY KEY,
                                        name text NOT NULL,
                                        password text NOT NULL,
                                        tfa text
                                        ); """
        
        sql_create_text_table = """ CREATE TABLE IF NOT EXISTS text (
                                        id integer PRIMARY KEY,
                                        user text NOT NULL,
                                        submitted_text text NOT NULL,
                                        result_text text NOT NULL
                                ); """

        sql_create_textresults_table = """ CREATE TABLE IF NOT EXISTS results (
                                            id integer PRIMARY KEY,
                                            spellcheck_results text NOT NULL
                                ); """

        sql_create_timestamp_table = """ CREATE TABLE IF NOT EXISTS timestamp (
                                            id integer PRIMARY KEY,
                                            user text NOT NULL,
                                            login_time date,
                                            logout_time date
                                ); """
        # create tables 
        with sqlite3.connect(database) as conn:
            create_table(conn, sql_create_users_table)
            print('created the users table')
            create_table(conn, sql_create_timestamp_table)
            print('created the timestamp table')
            create_table(conn, sql_create_text_table)
            print('created the text table')
            create_table(conn, sql_create_textresults_table)
            print('created the results table')
            create_admin(conn)
        conn.close()
    else:
        print('database exists')

# REGISTER
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        usr = form.username.data
        psw = form.password.data
        tfa = form.tfa.data
        # establish DB connection
        with sqlite3.connect(database) as conn:
            ind = check_users(conn, usr)
            if ind:
                psw_hash = generate_password_hash(psw)
                if tfa == '':
                    user = (usr, psw_hash, '')
                    create_users(conn, user)
                    success_status = 'Success, account has been created'
                    return render_template('register.html', title='Register', form=form, success_status=success_status)
                else:
                    user = (usr, psw_hash, tfa)
                    create_users(conn, user)
                    success_status = 'Success, account has been created'
                    return render_template('register.html', title='Register', form=form, success_status=success_status)
            else:
                failure_status = 'Failure, username must be unique'
                return render_template('register.html', title='Register', form=form, failure_status=failure_status)
            conn.close()
    else:
        return render_template('register.html', title='Register', form=form)

# LOGIN_REQUIRED
def login_required(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'username' in session:
			return f(*args, **kwargs)
		else:
			flash('You need to login first.')
			return redirect(url_for('login'))
	return wrap

@app.route('/')
def index():
    if 'username' in session:
        return 'Logged in as %s' % escape(session['username'])
    return 'You are not logged in'

# LOGOUT
@app.route('/logout')
@login_required
def logout():
    # flask_login.logout_user()
    current_user = escape(session['username'])
    session.pop('username', None)
    with sqlite3.connect(database) as conn:
        log_time(conn, 'logout', current_user)
    conn.close()
    flash('You are now logged out')
    return redirect(url_for('login'))

# LOGIN
@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        usr = form.username.data
        psw = form.password.data
        tfa = form.tfa.data
        # establish DB connection 
        with sqlite3.connect(database) as conn:
            cr = conn.cursor()
            cr.execute("SELECT * FROM users WHERE name = ?", (usr,))
            data = cr.fetchone()
            # need to set user login timer to N/A
            if data is None:
                result = 'Incorrect - username and password DO NOT match'                
                return render_template('login.html', title='Sign in', form=form, result=result)
            if usr == data[1]:
                print(data)
                psw_check = check_password_hash(data[2], psw)
                if tfa == '':
                    if usr == data[1] and psw_check:
                        session['username'] = usr
                        log_time(conn, 'login', usr)
                        result='Success - username, password, and tfa match'
                        return render_template('login.html', title='Sign in', form=form, result=result)
                    else:
                        result = 'Incorrect - username and password DO NOT match'
                        return render_template('login.html', title='Sign in', form=form, result=result)
                else:
                    if usr == data[1] and psw_check and data[3] == tfa:
                        session['username'] = usr
                        log_time(conn, 'login', usr)
                        result='Success - username, password, and tfa match'
                        return render_template('login.html', title='Sign in', form=form, result=result)
                    elif usr == data[1] and psw_check and data[3] != tfa:
                        result='Incorrect - tfa is incorrect'
                        return render_template('login.html', title='Sign in', form=form, result=result)
                    else:                        
                        result = 'Incorrect - username and password DO NOT match'
                        return render_template('login.html', title='Sign in', form=form, result=result)
            conn.close()
    return render_template('login.html', title='Sign in', form=form)

# SPELLCHECK
@app.route('/spell_check', methods=['GET','POST'])
@login_required
def spell_check():
    form = SpellcheckForm()
    if form.validate_on_submit():
        text = form.text.data
        f = open("text.txt","w")
        f.write(text)
        f.close()
        data = subprocess.check_output("./a.out ./text.txt ./wordlist.txt", shell=True)
        results = data.decode().strip().replace("\n",", ")
        current_user = escape(session['username'])
        with sqlite3.connect(database) as conn:
            store_text(conn, current_user, text, results)
        conn.close()
        return render_template('spell_check.html', title='Misspelled', form=form, results=results, text=text)
    else:
        return render_template('spell_check.html', title='Spellcheck', form=form)

@app.route('/history', methods=['GET','POST'])
def history():
    form = HistoryForm()
    current_user = escape(session['username'])
    # route for admin
    if current_user == 'admin':
        with sqlite3.connect(database) as conn:
            userquery = form.userquery.data
            query = retrieve_queries(conn, userquery)
            numqueries = len(query)
            return render_template('history_admin_view.html', title='history_admin_view', form=form, numqueries=numqueries, query=query)
    # route for regular user
    else:
        with sqlite3.connect(database) as conn:
            query = retrieve_queries(conn, current_user)
            numqueries = len(query)
        return render_template('history.html', title='History', form=form, numqueries=numqueries, query=query)

@app.route('/history/query<int:num>')
def query(num):
    with sqlite3.connect(database) as conn:
        queryid = num
        cr = conn.cursor()
        cr.execute("SELECT * FROM text WHERE id = ?", (num,))
        data = cr.fetchall()
        print(data)
        if len(data) == 0:
            return render_template('not_found_page.html')
        username = data[0][1]
        querytext = data[0][2]
        queryresults = data[0][3]
    conn.close()
    return render_template('query.html', queryid=queryid, username=username, querytext=querytext, queryresults=queryresults)

@app.route('/login_history', methods=['GET','POST'])
def login_history():
    current_user = escape(session['username'])
    form = LoginHistory()
    if current_user == 'admin':
        if form.validate_on_submit():
            usr = form.userid.data
            with sqlite3.connect(database) as conn:
                cr = conn.cursor()
                cr.execute("SELECT * FROM timestamp WHERE user = ?", (usr,))
                data = cr.fetchall()
                table = PrettyTable(["LOGIN ID", "USERNAME", "LOGIN TIME", "LOGOUT TIME"])
                username = login_time = logout_time = []
                for i in range (len(data)):
                    login_word = 'login{}'.format(data[i][0]) + '_time'
                    logout_word = 'logout{}'.format(data[i][0]) + '_time'
                    table.add_row(['login{}'.format(data[i][0]), data[i][1], data[i][2], data[i][3]])
            return render_template('login_history.html', form=form, data=data, tbl=table.get_html_string(attributes = {"class": "foo"}))
        else:
            return render_template('login_history.html', form=form)
    else:
        return render_template('unauthorized_page.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
