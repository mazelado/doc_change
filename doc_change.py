# TODO: Improvement - use Flask-Bootstrap to simplify templates
# TODO: Improvement - use SQLAlchemy to switch databases easily, move to MySQL?
# TODO: Improvement - use Flask-Security for better authentication
# TODO: Improvement - use Flask-RESTful to create REST API
# TODO: Improvement - break into modules (views separated)
# TODO: Try Django to see how it compares

import logging
import os
import sqlite3
import sys
from datetime import datetime

from flask import Flask, request, render_template, session, g, redirect, url_for, abort, flash
from flask_wtf import FlaskForm
from passlib.context import CryptContext
from wtforms import StringField, PasswordField, TextAreaField, HiddenField, SelectField, DateField
from wtforms.validators import DataRequired, Length, EqualTo, Email, Optional

# Flask setup
app = Flask(__name__)
app.config.from_object(__name__)
app.config.update(dict(
    DATABASE=os.path.join(app.root_path, 'doc_change.db'),
    SECRET_KEY=b'\x80\xfd\x11\xef\xad\xe7\x92\x04j1\xcdP\x0b\x0c\xc3\xb8\xf3:\xb6S\xb8o\xb0\xc0'
))
app.config.from_envvar('CHANGE_FLASK_SETTINGS', silent=True)

# Passlib setup
pwd_context = CryptContext(schemes=['pbkdf2_sha256', 'des_crypt'], deprecated='auto')


# Logic ----------------------------------------------------------------------------------------------------------------
def connect_db():
    """
    Connects to the specific database.
    """
    con = sqlite3.connect(app.config['DATABASE'])
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


@app.cli.command('initdb')
def initdb_command():
    """
    Initializes the database.
    """
    init_db()
    print('Initialized the database.')


def get_db():
    """
    Opens a new database connection if there is none yet for the
    current application context.
    """
    if not hasattr(g, 'sqlite_db'):
        g.sqlite_db = connect_db()
    return g.sqlite_db


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


@app.teardown_appcontext
def close_db(error):
    """
    Closes the database again at the end of the request.
    """
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()


def flash_errors(form):
    for field, errors in form.errors.items():
        for error in errors:
            print('Error in the %s field - %s' % (
                getattr(form, field).label.text,
                error
            ), file=sys.stderr)
            flash(u"Error in the %s field - %s" % (
                getattr(form, field).label.text,
                error
            ))


# Views ----------------------------------------------------------------------------------------------------------------
@app.errorhandler(401)
def not_found_error(error):
    """
    Displays a custom 401 Unauthorized message.
    """
    return render_template('401.html', error=error)


@app.errorhandler(404)
def not_found_error(error):
    """
    Displays a custom 404 Not Found message.
    """
    return render_template('404.html', error=error)


@app.errorhandler(500)
def internal_server_error(error):
    """
    Display a custom 500 Internal Server Error message.
    """
    return render_template('500.html', error=error)


@app.route('/')
def show_start():
    """
    Display the Start page.

    :return:
    """
    return render_template('start.html')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])


@app.route('/login/')
def show_login():
    """
    Display the Login page.

    :return:
    """
    error = None

    # CSRF is disabled because it prevented this from working and I couldn't figure out why it was missing
    # TODO: Figure out why CSRF token is missing and re-enable
    #   (Related to FlaskWTFDeprecationWarning: "csrf_enabled" is deprecated and will be removed in 1.0. Set "meta.csrf" instead. ?)
    form = LoginForm(request.form, csrf_enabled=False)

    return render_template('login.html', form=form, error=error)


@app.route('/do_login/', methods=['POST'])
def do_login():
    """
    Log a user into the system.

    :return:
    """
    error = None

    # CSRF is disabled because it prevented this from working and I couldn't figure out why it was missing
    # TODO: Figure out why CSRF token is missing and re-enable
    #   (Related to FlaskWTFDeprecationWarning: "csrf_enabled" is deprecated and will be removed in 1.0. Set "meta.csrf" instead. ?)
    form = LoginForm(request.form, csrf_enabled=False)

    if form.validate():
        username_from_form = form.username.data
        password_from_form = form.password.data

        # Validate login information
        query = """
                SELECT [username], 
                       [password], 
                       [first_name], 
                       [last_name]
                FROM   [users]
                WHERE  [users].[username] = ?;
                """
        args = [username_from_form]
        rows = query_db(query, args, one=True)
        if len(rows) > 0:
            username_from_db = rows[0]
            hash_from_db = rows[1]
            first_name_from_db = rows[2]
            last_name_from_db = rows[3]

        if len(rows) == 0 or pwd_context.verify(password_from_form, hash_from_db) is False:
            error = 'Invalid username or password.'
        else:
            session['logged_in'] = True
            session['username'] = username_from_db
            session['name'] = ' '.join([first_name_from_db, last_name_from_db]).strip()

            # Get user permissions
            query = """
                    SELECT [can_view_user], 
                           [can_add_user], 
                           [can_edit_user], 
                           [can_delete_user], 
                           [can_view_doc], 
                           [can_add_doc], 
                           [can_edit_doc], 
                           [can_delete_doc], 
                           [can_send_doc]
                    FROM   [users]
                    WHERE  [users].[username] = ?;
                    """
            args = [session['username']]
            rows = query_db(query, args, one=False)

            session['can_view_user'] = rows[0][0]
            session['can_add_user'] = rows[0][1]
            session['can_edit_user'] = rows[0][2]
            session['can_delete_user'] = rows[0][3]
            session['can_view_doc'] = rows[0][4]
            session['can_add_doc'] = rows[0][5]
            session['can_edit_doc'] = rows[0][6]
            session['can_delete_doc'] = rows[0][7]
            session['can_send_doc'] = rows[0][8]

            flash('Logged in as {}.'.format(session['name']))
            return redirect(url_for('show_dashboard'))

        return redirect(url_for('show_login', error=error))


@app.route('/logout/')
def do_logout():
    """
    Log the user out of the system.

    :return:
    """
    name = session['name']

    # Clear session variables
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('last_name', None)
    session.pop('first_name', None)
    session.pop('name', None)
    session.pop('can_view_user', None)
    session.pop('can_add_user', None)
    session.pop('can_edit_user', None)
    session.pop('can_delete_user', None)
    session.pop('can_view_doc', None)
    session.pop('can_add_doc', None)
    session.pop('can_edit_doc', None)
    session.pop('can_delete_doc', None)
    session.pop('can_send_doc', None)

    flash('{} logged out.'.format(name))
    return redirect(url_for('show_start'))


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email Address', validators=[DataRequired(), Length(min=6, max=50), Email()])
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=2, max=30)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=30)])
    password = PasswordField('Password',
                             validators=[DataRequired(), EqualTo('confirm', message='Passwords do not match.'),
                                         Length(min=8, max=20)])
    confirm = PasswordField('Confirm Password', validators=[DataRequired()])


@app.route('/register/')
def show_register_user():
    """
    Display the Register User page.
    """
    error = None

    # CSRF is disabled because it prevented this from working and I couldn't figure out why it was missing
    # TODO: Figure out why CSRF token is missing and re-enable
    form = RegistrationForm(request.form, csrf_enabled=False)

    return render_template('register_user.html', form=form, error=error)


@app.route('/do_register/', methods=['POST'])
def insert_user():
    """
    Insert a row into the users table.

    :return:
    """
    # Check permissions
    if not session['logged_in'] or not session['can_add_user']:
        abort(401)

    error = None

    # CSRF is disabled because it prevented this from working and I couldn't figure out why it was missing
    # TODO: Figure out why CSRF token is missing and re-enable
    form = RegistrationForm(request.form, csrf_enabled=False)

    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        pwd_hash = pwd_context.hash(form.password.data)

        db = get_db()
        # Check if user already exists
        query = """
                SELECT [username]
                FROM   [users]
                WHERE  [username] = ?;
                """
        args = [username]
        results = query_db(query, args)

        if results:
            error = 'Invalid username.'
        else:
            # Add user to database
            query = """
                    INSERT INTO [users]
                        ([username], 
                        [email], 
                        [first_name], 
                        [last_name], 
                        [password])
                        VALUES (?, ?, ?, ?, ?);
                    """
            args = [username, email, first_name, last_name, pwd_hash]
            db.execute(query, args)
            db.commit()

            flash('New user \'{}\' was successfully added.'.format(username))
            return redirect(url_for('show_start'))

    return render_template('register_user.html', form=form, error=error)


@app.route('/update_user/')
def update_user():
    """
    Edit user profile.
    """
    error = None
    if not session['logged_in'] and not session['can_edit_user']:
        abort(401)

    return render_template('edit_profile.html', error=error)


@app.route('/update_users_as_admin/')
def update_users_as_admin():
    """
    Edit system users.
    """
    error = None
    if not session['logged_in'] and not session['can_edit_user']:
        abort(401)

    return render_template('edit_users.html', error=error)


@app.route('/dashboard/')
def show_dashboard():
    """
    Display user dashboard.

    :return:
    """

    error = None
    if not session['logged_in'] or not session['can_view_doc']:
        abort(401)

    # TODO: Show Incomplete Doc Changes (doc_change exists, but affected_part_nos = 0 or requests = 0)
    # Does not appear to be possible with SQLite

    # # Get Incomplete Doc Changes
    # query = """
    #
    #         """
    # args = [session['name']]
    # inc_results = query_db(query, args)

    # Get Pending Requests
    query = """
            SELECT [doc_changes].[id],  
                   [doc_changes].[submit_date],   
                   [doc_changes].[problem_desc], 
                   [doc_changes].[proposal_desc],
                   GROUP_CONCAT ([affected_parts].[part_no], ", ") AS [part_nos]
            FROM   [doc_changes]
                   INNER JOIN [request] ON [request].[doc_change_id] = [doc_changes].[id]
                   INNER JOIN [affected_parts] ON [affected_parts].[doc_change_id] = [doc_changes].[id]
            WHERE  ([doc_changes].[status_id] = 1)
                   AND ([request].[stakeholder_name] = ?)
            GROUP  BY [doc_changes].[id];    
            """
    args = [session['name']]
    req_results = query_db(query, args)

    # Get Pending Orders
    query = """
            SELECT [order].[doc_change_id], 
                   [document_types].[document_name], 
                   [order].[notes],  
                   [order].[due_date]
            FROM   [order]
                   INNER JOIN [document_types] ON [document_types].[id] = [order].[document_type_id]
            WHERE  ([order].[responsible_name] = ?)
                   AND ([order].[completed_date] = "");
            """
    args = [session['name']]
    ord_results = query_db(query, args)

    # Get Pending Notices
    query = """
            SELECT [doc_changes].[id], 
                   [doc_changes].[proposed_implement_date]
            FROM   [doc_changes]
                   INNER JOIN [notice] ON [notice].[doc_change_id] = [doc_changes].[id]
            WHERE  ([notice].[authorize_name] = ?)
                   AND ([notice].[authorize_date] = "")
            GROUP  BY [doc_changes].[id];
            """
    args = [session['name']]
    ntc_results = query_db(query, args)

    return render_template('dashboard.html', error=error, req_results=req_results, ord_results=ord_results,
                           ntc_results=ntc_results)


@app.route('/dashboard_as_admin/')
def show_dashboard_as_admin():
    """
    Display Administrator dashboard.

    :return:
    """
    error = None

    # Check permissions
    if not session['logged_in'] or not session['can_view_doc'] or not session['name'] == 'Administrator':
        abort(401)

    # TODO: Get Problems (doc_change exists, but affected_part_nos = 0 or requests = 0)

    # Get Requests from DB
    query = """
            SELECT [doc_changes].[id],  
                   [doc_changes].[submit_date],   
                   [doc_changes].[problem_desc], 
                   [doc_changes].[proposal_desc],
                   GROUP_CONCAT ([affected_parts].[part_no], ", ") AS [part_nos]
            FROM   [doc_changes]
                   INNER JOIN [request] ON [request].[doc_change_id] = [doc_changes].[id]
                   INNER JOIN [affected_parts] ON [affected_parts].[doc_change_id] = [doc_changes].[id]
            WHERE  ([doc_changes].[status_id] = 1)
            GROUP  BY [doc_changes].[id];    
            """
    args = []
    req_results = query_db(query, args)

    # Get Orders from DB
    query = """
            SELECT [order].[doc_change_id], 
                   [document_types].[document_name], 
                   [order].[notes],  
                   [order].[due_date]
            FROM   [order]
                   INNER JOIN [document_types] ON [document_types].[id] = [order].[document_type_id]
            WHERE  ([order].[completed_date] = "");
            """
    args = []
    ord_results = query_db(query, args)

    # Get Notices from DB
    query = """
            SELECT [doc_changes].[id], 
                   [doc_changes].[proposed_implement_date]
            FROM   [doc_changes]
                   INNER JOIN [notice] ON [notice].[doc_change_id] = [doc_changes].[id]
            WHERE  ([notice].[authorize_date] = "")
            GROUP  BY [doc_changes].[id];
            """
    args = []
    ntc_results = query_db(query, args)

    return render_template('dashboard.html', error=error, req_results=req_results, ord_results=ord_results,
                           ntc_results=ntc_results)


@app.route('/doc_change/all/')
def show_all_doc_changes():
    """
    Display all document changes in a filterable list.
    """

    # TODO: Change table so that it can sort id, submit_date by value, not alphabetical
    # https://github.com/wenzhixin/bootstrap-table/issues/821

    error = None
    if not session['logged_in'] or not session['can_view_doc']:
        abort(401)

    query = """
            SELECT [doc_changes].[id], 
                   [doc_change_status].[status], 
                   [doc_changes].[submit_date], 
                   [doc_changes].[submit_by], 
                   [doc_changes].[problem_desc], 
                   [doc_changes].[proposal_desc], 
                   GROUP_CONCAT ([affected_parts].[part_no], ", ") AS [part_nos]
            FROM   [doc_changes]
                   INNER JOIN [affected_parts] ON [affected_parts].[doc_change_id] = [doc_changes].[id]
                   INNER JOIN [doc_change_status] ON [doc_change_status].[id] = [doc_changes].[status_id]
            GROUP  BY [doc_changes].[id];
            """
    args = []
    rows = query_db(query, args)

    return render_template('view_all.html', error=error, rows=rows)


class DocChangeForm(FlaskForm):
    id = HiddenField('Row ID')
    status_id = SelectField('Status', coerce=int, render_kw={'disabled': True})
    status = StringField('Status', render_kw={'readonly': True})
    submit_by = StringField('Submit By', render_kw={'readonly': True})
    submit_date = StringField('Submit Date', render_kw={'readonly': True})
    problem_desc = TextAreaField('Problem Description', validators=[DataRequired()])
    proposal_desc = TextAreaField('Proposal Description', validators=[DataRequired()])
    proposed_implement_date = StringField('Proposed Implementation Date', validators=[DataRequired()])
    actual_implement_date = StringField('Actual Implementation Date', validators=[Optional()],
                                        render_kw={'readonly': True})


class DocChangeAffectedPartsForm(FlaskForm):
    id = HiddenField('Row ID')
    doc_change_id = HiddenField('Document Change ID')
    part_no = StringField('Part No', validators=[DataRequired()])
    rev = StringField('Revision')
    routing = StringField('Routing')
    desc = StringField('Description', validators=[DataRequired()])


class DocChangeRequestForm(FlaskForm):
    id = HiddenField('Row ID')
    doc_change_id = HiddenField('Document Change ID')
    stakeholder_name = StringField('Name', validators=[DataRequired(), Length(min=2)])
    stakeholder_email = StringField('Email Address', validators=[DataRequired(), Length(min=6, max=50), Email()])
    status_id = SelectField('Status', coerce=int)
    status = StringField('Status')
    sent_date = StringField('Date Sent', validators=[Optional()])
    approval_date = StringField('Date Approved', validators=[Optional()])
    notes = TextAreaField('Notes')


class DocChangeOrderForm(FlaskForm):
    id = HiddenField('Row ID')
    doc_change_id = HiddenField('Document Change ID')
    document_type_id = SelectField('Document Type', coerce=int)
    document_name = StringField('Document Type')
    notes = TextAreaField('Notes')
    responsible_name = StringField('Name', validators=[DataRequired(), Length(min=2)])
    responsible_email = StringField('Email Address', validators=[DataRequired(), Length(min=6, max=50), Email()])
    due_date = StringField('Due Date', validators=[DataRequired()])
    sent_date = StringField('Sent Date')
    completed_date = StringField('Completed Date')
    new_revision = StringField('New Revision')


class DocChangeNoticeForm(FlaskForm):
    id = HiddenField('Row ID')
    doc_change_id = HiddenField('Document Change ID')
    authorize_name = StringField('Name', validators=[DataRequired(), Length(min=2)])
    authorize_email = StringField('Email Address', validators=[DataRequired(), Length(min=6, max=50), Email()])
    sent_date = StringField('Sent Date', validators=[Optional()])
    authorize_date = StringField('Authorized Date', validators=[Optional()])
    notes = TextAreaField('Notes')


@app.route('/doc_change/')
@app.route('/doc_change/<int:doc_change_id>/')
def show_doc_change(doc_change_id=0):
    """
    View a Document Change from the DB

    :param doc_change_id:
    :return:
    """

    # Check permissions
    if not session['logged_in'] or not session['can_view_doc']:
        abort(401)

    error = None

    doc_change_form = DocChangeForm(request.form, csrf_enabled=False)
    doc_change_affected_parts_form = DocChangeAffectedPartsForm(request.form, csrf_enabled=False,
                                                                doc_change_id=doc_change_id)
    doc_change_request_form = DocChangeRequestForm(request.form, csrf_enabled=False, doc_change_id=doc_change_id)
    doc_change_order_form = DocChangeOrderForm(request.form, csrf_enabled=False, doc_change_id=doc_change_id)
    doc_change_notice_form = DocChangeNoticeForm(request.form, csrf_enabled=False, doc_change_id=doc_change_id)

    # Get Document Change Statuses from DB
    query = """
            SELECT [doc_change_status].[id], 
                   [doc_change_status].[status]
            FROM   [doc_change_status]
            ORDER  BY [doc_change_status].[id];
            """
    args = []
    doc_change_statuses = query_db(query, args)
    doc_change_form.status_id.choices = [(row['id'], row['status']) for row in
                                         doc_change_statuses]

    if doc_change_id == 0:  # New Doc Change
        return render_template('doc_change.html', error=error, doc_change_id=doc_change_id,
                               doc_change_form=doc_change_form, doc_change_request_form=doc_change_request_form,
                               doc_change_affected_parts_form=doc_change_affected_parts_form)
    else:  # Existing Doc Change
        # Get data from doc_changes table
        query = """
                SELECT [doc_changes].[status_id], 
                       [doc_changes].[submit_date], 
                       [doc_changes].[submit_by], 
                       [doc_changes].[problem_desc], 
                       [doc_changes].[proposal_desc], 
                       [doc_changes].[proposed_implement_date], 
                       [doc_changes].[actual_implement_date]
                FROM   [doc_changes]
                       INNER JOIN [doc_change_status] ON [doc_change_status].[id] = [doc_changes].[status_id]
                WHERE  [doc_changes].[id] = ?;
                """
        args = [doc_change_id]
        doc_change_row = query_db(query, args, one=True)

        # Check that records exist in DB
        if not doc_change_row:
            redirect(url_for('show_doc_change', doc_change_id=0))

        # Get data from affected_part_no table
        query = """
                SELECT [affected_parts].[id],
                       [affected_parts].[doc_change_id],
                       [affected_parts].[part_no], 
                       [affected_parts].[revision], 
                       [affected_parts].[routing], 
                       [affected_parts].[description]
                FROM   [affected_parts]
                WHERE  [affected_parts].[doc_change_id] = ?;
                """
        args = [doc_change_id]
        affected_parts_rows = query_db(query, args)

        # Get Requests from DB
        query = """
                SELECT [request].[id],
                       [request].[doc_change_id],
                       [request].[stakeholder_name], 
                       [request].[stakeholder_email], 
                       [request_status].[status], 
                       [request].[sent_date], 
                       [request].[approval_date], 
                       [request].[notes]
                FROM   [request]
                       INNER JOIN [request_status] ON [request_status].[id] = [request].[status_id]
                WHERE  [request].[doc_change_id] = ?;
                """
        args = [doc_change_id]
        request_rows = query_db(query, args)

        # Get Orders from DB
        query = """
                SELECT [order].[id], 
                       [order].[doc_change_id],
                       [order].[document_type_id], 
                       [document_types].[document_name], 
                       [order].[notes], 
                       [order].[responsible_name], 
                       [order].[responsible_email], 
                       [order].[due_date], 
                       [order].[sent_date], 
                       [order].[completed_date], 
                       [order].[new_revision]
                FROM   [order]
                       INNER JOIN [document_types] ON [document_types].[id] = [order].[document_type_id]
                WHERE  [order].[doc_change_id] = ?;
                """
        args = [doc_change_id]
        order_rows = query_db(query, args)

        # Get Document Types from DB
        query = """
                SELECT [document_types].[id], 
                       [document_types].[document_name]
                FROM   [document_types]
                ORDER  BY [document_types].[document_name];
                """
        args = []
        order_document_types = query_db(query, args)
        doc_change_order_form.document_type_id.choices = [(row['id'], row['document_name']) for row in
                                                          order_document_types]

        # Get Notices from DB
        query = """
                SELECT [notice].[id], 
                       [notice].[doc_change_id], 
                       [notice].[authorize_name], 
                       [notice].[authorize_email], 
                       [notice].[sent_date], 
                       [notice].[authorize_date], 
                       [notice].[notes]
                FROM   [notice]
                WHERE  [notice].[doc_change_id] = ?
                GROUP BY [notice].[authorize_name];
                """
        args = [doc_change_id]
        notice_rows = query_db(query, args)

        # Populate form with data
        doc_change_form.status_id.data = doc_change_row['status_id']
        doc_change_form.submit_date.data = doc_change_row['submit_date']
        doc_change_form.submit_by.data = doc_change_row['submit_by']
        doc_change_form.problem_desc.data = doc_change_row['problem_desc']
        doc_change_form.proposal_desc.data = doc_change_row['proposal_desc']
        doc_change_form.proposed_implement_date.data = doc_change_row['proposed_implement_date']
        doc_change_form.actual_implement_date.data = doc_change_row['actual_implement_date']

        return render_template('doc_change.html',
                               error=error,
                               doc_change_id=doc_change_id,
                               doc_change_form=doc_change_form,
                               doc_change_affected_parts_form=doc_change_affected_parts_form,
                               doc_change_request_form=doc_change_request_form,
                               doc_change_order_form=doc_change_order_form,
                               doc_change_notice_form=doc_change_notice_form,
                               affected_parts_rows=affected_parts_rows,
                               request_rows=request_rows,
                               order_rows=order_rows,
                               notice_rows=notice_rows)


@app.route('/insert_doc_change/', methods=['POST'])
def insert_doc_change():
    """
    Insert a new Document Change into the DB

    :return:
    """

    error = None

    doc_change_form = DocChangeForm(request.form, csrf_enabled=False)

    # Get Document Change Statuses from DB
    query = """
                SELECT [doc_change_status].[id], 
                       [doc_change_status].[status]
                FROM   [doc_change_status]
                ORDER  BY [doc_change_status].[id];
                """
    args = []
    doc_change_statuses = query_db(query, args)
    doc_change_form.status_id.choices = [(row['id'], row['status']) for row in
                                         doc_change_statuses]

    # Save data to variables
    doc_change_id = 0
    doc_change_form.status_id.data = 1
    status_id = doc_change_form.status_id.data
    submit_by = session['name']
    submit_date = '{dt.month}/{dt.day}/{dt.year}'.format(dt=datetime.now())
    proposed_implement_date = doc_change_form.proposed_implement_date.data
    problem_desc = doc_change_form.problem_desc.data
    proposal_desc = doc_change_form.proposal_desc.data

    # Check permissions
    if not session['logged_in'] or not session['can_add_doc']:
        abort(401)

    if doc_change_form.validate_on_submit():
        # Add doc change to database
        db = get_db()
        query = """
                INSERT INTO [doc_changes]
                    ([status_id],
                    [submit_by], 
                    [submit_date], 
                    [proposed_implement_date], 
                    [problem_desc], 
                    [proposal_desc])
                    VALUES (?, ?, ?, ?, ?, ?);
                """
        args = [status_id, submit_by, submit_date, proposed_implement_date, problem_desc, proposal_desc]
        cur = db.cursor()
        cur.execute(query, args)

        # Store ID of last row added
        doc_change_id = cur.lastrowid

        db.commit()

        flash('Document Change {} was successfully added.'.format(doc_change_id))

    flash_errors(doc_change_form)
    return redirect(url_for('show_doc_change', error=error, doc_change_id=doc_change_id))


@app.route('/update_doc_change/<int:doc_change_id>/', methods=['POST'])
def update_doc_change(doc_change_id):
    """
    Update a row in doc_change table.

    :param doc_change_id:
    :return:
    """

    error = None

    doc_change_form = DocChangeForm(request.form, csrf_enabled=False)

    # Get Document Change Statuses from DB
    query = """
                    SELECT [doc_change_status].[id], 
                           [doc_change_status].[status]
                    FROM   [doc_change_status]
                    ORDER  BY [doc_change_status].[id];
                    """
    args = []
    doc_change_statuses = query_db(query, args)
    doc_change_form.status_id.choices = [(row['id'], row['status']) for row in
                                         doc_change_statuses]
    doc_change_form.status_id.data = 1 # Why do I have to do this if it's not referenced anywhere in this function?

    # Check permissions
    if not session['logged_in'] or not session['can_add_doc']:
        abort(401)

    if doc_change_form.validate_on_submit():
        problem_desc = doc_change_form.problem_desc.data
        proposal_desc = doc_change_form.proposal_desc.data
        proposed_implement_date = doc_change_form.proposed_implement_date.data

        # Update doc change
        db = get_db()
        query = """
                UPDATE
                    [doc_changes]
                SET
                    [problem_desc] = ?, 
                    [proposal_desc] = ?, 
                    [proposed_implement_date] = ?
                WHERE
                    [doc_changes].[id] = ?;
                """
        args = [problem_desc, proposal_desc, proposed_implement_date, doc_change_id]
        db.execute(query, args)
        db.commit()

        flash('Document Change {} was successfully updated.'.format(doc_change_id))

    flash_errors(doc_change_form)
    return redirect(url_for('show_doc_change', error=error, doc_change_id=doc_change_id))


@app.route('/add_affected_part_no/', methods=['POST'])
def insert_affected_part_no():
    """
    Insert a row into affected_part_no table.

    :return:
    """
    error = None

    doc_change_affected_parts_form = DocChangeAffectedPartsForm(request.form, csrf_enabled=False)

    # Save all form data to variables
    doc_change_id = doc_change_affected_parts_form.doc_change_id.data
    part_no = doc_change_affected_parts_form.part_no.data
    desc = doc_change_affected_parts_form.desc.data
    rev = doc_change_affected_parts_form.rev.data
    routing = doc_change_affected_parts_form.routing.data

    # Check permissions
    if not session['logged_in'] or not session['can_edit_doc']:
        abort(401)

    if doc_change_affected_parts_form.validate_on_submit():
        # Insert data into DB
        db = get_db()
        query = """
                INSERT INTO [affected_parts]
                    ([doc_change_id], 
                    [part_no], 
                    [description], 
                    [revision], 
                    [routing])
                    VALUES (?, ?, ?, ?, ?);
                """
        args = [doc_change_id, part_no, desc, rev, routing]
        db.execute(query, args)
        db.commit()

        flash('Part number {} was successfully added.'.format(part_no))

    return redirect(url_for('show_doc_change', error=error, doc_change_id=doc_change_id))


@app.route('/edit_affected_part_no/', methods=['POST'])
def update_affected_part_no():
    """
    Update a row in affected_part_no table.

    :return:
    """
    doc_change_affected_parts_form = DocChangeAffectedPartsForm(request.form, csrf_enabled=False)

    # Save all form data to variables
    row_id = doc_change_affected_parts_form.id.data
    doc_change_id = doc_change_affected_parts_form.doc_change_id.data
    part_no = doc_change_affected_parts_form.part_no.data
    desc = doc_change_affected_parts_form.desc.data
    rev = doc_change_affected_parts_form.rev.data
    routing = doc_change_affected_parts_form.routing.data

    # Check permissions
    if not session['logged_in'] or not session['can_edit_doc']:
        abort(401)

    if doc_change_affected_parts_form.validate_on_submit():
        # Insert data into DB
        db = get_db()
        query = """
                UPDATE
                    [affected_parts]
                SET
                    [part_no] = ?,
                    [description] = ?,
                    [revision] = ?,
                    [routing] = ?
                WHERE
                    [affected_parts].[id] = ?;
                """
        args = [part_no, desc, rev, routing, row_id]
        db.execute(query, args)
        db.commit()

    return redirect(url_for('show_doc_change', doc_change_id=doc_change_id))


@app.route('/delete_affected_part_no/<int:row_id>/', methods=['POST'])
def delete_affected_part_no(row_id):
    """
    Delete a row from affected_part_no table.

    :param row_id:
    :return:
    """
    # Check permissions
    if not session['logged_in'] or not session['can_edit_doc']:
        abort(401)

    # Request arguments
    doc_change_id = request.args.get('doc_change_id')

    # Insert data into DB
    db = get_db()
    query = """
            DELETE FROM
                [affected_parts]
            WHERE
                [affected_parts].[id] = ?;
            """
    args = [row_id]
    db.execute(query, args)
    db.commit()

    flash('Part was successfully deleted.')

    return redirect(url_for('show_doc_change', doc_change_id=doc_change_id))


@app.route('/insert_request/', methods=['POST'])
def insert_request():
    """
    Insert a row into requests table.

    :return:
    """
    error = None

    doc_change_requests_form = DocChangeRequestForm(request.form, csrf_enabled=False)

    # Save all form data to variables
    doc_change_id = doc_change_requests_form.doc_change_id.data
    stakeholder_name = doc_change_requests_form.stakeholder_name.data
    stakeholder_email = doc_change_requests_form.email.data
    status_id = 1
    notes = doc_change_requests_form.notes.data

    # Check permissions
    if not session['logged_in'] or not session['can_edit_doc']:
        abort(401)

    if doc_change_requests_form.validate_on_submit():
        # Insert data into DB
        db = get_db()
        query = """
                INSERT INTO [request]
                    ([doc_change_id], 
                    [stakeholder_name], 
                    [stakeholder_email], 
                    [status_id], 
                    [notes])
                    VALUES (?, ?, ?, ?, ?);
                """
        args = [doc_change_id, stakeholder_name, stakeholder_email, status_id, notes]
        db.execute(query, args)
        db.commit()

        flash('Request stakeholder {} was successfully added.'.format(stakeholder_name))

    # flash_errors(doc_change_requests_form)
    return redirect(url_for('show_doc_change', error=error, doc_change_id=doc_change_id))


@app.route('/update_request/', methods=['POST'])
def update_request():
    """
    Update a row in requests table.

    :return:
    """
    doc_change_request_form = DocChangeRequestForm(request.form, csrf_enabled=False)

    # Save all form data to variables
    row_id = doc_change_request_form.id.data
    doc_change_id = doc_change_request_form.doc_change_id.data
    stakeholder_name = doc_change_request_form.stakeholder_name.data
    stakeholder_email = doc_change_request_form.email.data
    notes = doc_change_request_form.notes.data

    # Check permissions
    if not session['logged_in'] or not session['can_edit_doc']:
        abort(401)

    if doc_change_request_form.validate_on_submit():
        # Insert data into DB
        db = get_db()
        query = """
                UPDATE
                    [request]
                SET
                    [stakeholder_name] = ?,
                    [stakeholder_email] = ?,
                    [notes] = ?
                WHERE
                    [request].[id] = ?;
                """
        args = [stakeholder_name, stakeholder_email, notes, row_id]
        db.execute(query, args)
        db.commit()

        flash('Request stakeholder {} was successfully updated.'.format(stakeholder_name))

    return redirect(url_for('show_doc_change', doc_change_id=doc_change_id))


@app.route('/delete_request/<int:row_id>', methods=['POST'])
def delete_request(row_id):
    """
    Delete a row from requests table.

    :param row_id:
    :return:
    """
    # Check permissions
    if not session['logged_in'] or not session['can_edit_doc']:
        abort(401)

    # Request arguments
    doc_change_id = request.args.get('doc_change_id')

    # Insert data into DB
    db = get_db()
    query = """
                DELETE FROM
                    [request]
                WHERE
                    [request].[id] = ?;
                """
    args = [row_id]
    db.execute(query, args)
    db.commit()

    flash('Request was successfully deleted.')

    return redirect(url_for('show_doc_change', doc_change_id=doc_change_id))


@app.route('/insert_order/', methods=['POST'])
def insert_order():
    """
    Insert a row into order table.

    :return:
    """
    error = None

    doc_change_order_form = DocChangeOrderForm(request.form, csrf_enabled=False)

    # Get Document Types from DB
    query = """
            SELECT [document_types].[id], 
                   [document_types].[document_name]
            FROM   [document_types]
            ORDER  BY [document_types].[document_name];
            """
    args = []
    order_document_types = query_db(query, args)
    doc_change_order_form.document_type_id.choices = [(row['id'], row['document_name']) for row in
                                                      order_document_types]

    # Save all form data to variables
    doc_change_id = doc_change_order_form.doc_change_id.data
    document_type_id = doc_change_order_form.document_type_id.data
    notes = doc_change_order_form.notes.data
    responsible_name = doc_change_order_form.responsible_name.data
    responsible_email = doc_change_order_form.responsible_email.data
    due_date = doc_change_order_form.due_date.data
    new_revision = doc_change_order_form.new_revision.data

    # Check permissions
    if not session['logged_in'] or not session['can_edit_doc']:
        abort(401)

    if doc_change_order_form.validate_on_submit():
        # Insert data into DB
        db = get_db()
        query = """
                INSERT INTO [order]
                    ([doc_change_id],
                    [document_type_id],
                    [notes], 
                    [responsible_name], 
                    [responsible_email], 
                    [due_date],
                    [new_revision])
                    VALUES (?, ?, ?, ?, ?, ?, ?);
                """
        args = [doc_change_id, document_type_id, notes, responsible_name, responsible_email, due_date, new_revision]
        db.execute(query, args)
        db.commit()

        flash('Order was successfully added.')

    flash_errors(doc_change_order_form)
    return redirect(url_for('show_doc_change', error=error, doc_change_id=doc_change_id))


@app.route('/update_order/', methods=['POST'])
def update_order():
    """
    Update a row in order table.

    :return:
    """
    doc_change_order_form = DocChangeOrderForm(request.form, csrf_enabled=False)

    # Get Document Types from DB
    query = """
            SELECT [document_types].[id], 
                   [document_types].[document_name]
            FROM   [document_types]
            ORDER  BY [document_types].[document_name];
            """
    args = []
    order_document_types = query_db(query, args)
    doc_change_order_form.document_type_id.choices = [(row['id'], row['document_name']) for row in
                                                      order_document_types]

    # Save all form data to variables
    row_id = doc_change_order_form.id.data
    doc_change_id = doc_change_order_form.doc_change_id.data
    document_type_id = doc_change_order_form.document_type_id.data
    notes = doc_change_order_form.notes.data
    responsible_name = doc_change_order_form.responsible_name.data
    responsible_email = doc_change_order_form.responsible_email.data
    due_date = doc_change_order_form.due_date.data
    new_revision = doc_change_order_form.new_revision.data

    # Check permissions
    if not session['logged_in'] or not session['can_edit_doc']:
        abort(401)

    if doc_change_order_form.validate_on_submit():
        # Update data in DB
        db = get_db()
        query = """
                UPDATE
                    [order]
                SET
                    [document_type_id] = ?,
                    [notes] = ?,
                    [responsible_name] = ?,
                    [responsible_email] = ?,
                    [due_date] = ?,
                    [new_revision] = ?
                WHERE
                    [order].[id] = ?;
                """
        args = [document_type_id, notes, responsible_name, responsible_email, due_date, new_revision, row_id]
        db.execute(query, args)
        db.commit()

        flash('Order was successfully updated.')

    flash_errors(doc_change_order_form)
    return redirect(url_for('show_doc_change', doc_change_id=doc_change_id))


@app.route('/delete_order/<int:row_id>', methods=['POST'])
def delete_order(row_id):
    """
    Delete a row from order table.

    :param row_id:
    :return:
    """
    # Check permissions
    if not session['logged_in'] or not session['can_edit_doc']:
        abort(401)

    # Request arguments
    doc_change_id = request.args.get('doc_change_id')

    # Insert data into DB
    db = get_db()
    query = """
            DELETE FROM
                [order]
            WHERE
                [order].[id] = ?;
            """
    args = [row_id]
    db.execute(query, args)
    db.commit()

    flash('Order was successfully deleted.')

    return redirect(url_for('show_doc_change', doc_change_id=doc_change_id))


@app.route('/insert_notice/', methods=['POST'])
def insert_notice():
    """
    Insert a row into notice table.

    :return:
    """
    error = None

    doc_change_notice_form = DocChangeNoticeForm(request.form, csrf_enabled=False)

    # Save all form data to variables
    doc_change_id = doc_change_notice_form.doc_change_id.data
    authorize_name = doc_change_notice_form.authorize_name.data
    authorize_email = doc_change_notice_form.authorize_email.data
    notes = doc_change_notice_form.notes.data

    # Check permissions
    if not session['logged_in'] or not session['can_edit_doc']:
        abort(401)

    if doc_change_notice_form.validate_on_submit():
        # Insert data into DB
        db = get_db()
        query = """
                    INSERT INTO [notice]
                        ([doc_change_id], 
                        [authorize_name], 
                        [authorize_email], 
                        [notes])
                        VALUES (?, ?, ?, ?);
                    """
        args = [doc_change_id, authorize_name, authorize_email, notes]
        db.execute(query, args)
        db.commit()

        flash('Notice was successfully added.')

    flash_errors(doc_change_notice_form)
    return redirect(url_for('show_doc_change', error=error, doc_change_id=doc_change_id))


@app.route('/update_notice/', methods=['POST'])
def update_notice():
    """
    Update a row in notice table.

    :return:
    """
    doc_change_notice_form = DocChangeNoticeForm(request.form, csrf_enabled=False)

    # Save all form data to variables
    row_id = doc_change_notice_form.id.data
    doc_change_id = doc_change_notice_form.doc_change_id.data
    authorize_name = doc_change_notice_form.authorize_name.data
    authorize_email = doc_change_notice_form.authorize_email.data
    notes = doc_change_notice_form.notes.data

    # Check permissions
    if not session['logged_in'] or not session['can_edit_doc']:
        abort(401)

    if doc_change_notice_form.validate_on_submit():
        # Update data in DB
        db = get_db()
        query = """
                    UPDATE
                        [notice]
                    SET
                        [authorize_name] = ?,
                        [authorize_email] = ?,
                        [notes] = ?
                    WHERE
                        [notice].[id] = ?;
                    """
        args = [authorize_name, authorize_email, notes, row_id]
        db.execute(query, args)
        db.commit()

        flash('Notice was successfully updated.')

    flash_errors(doc_change_notice_form)
    return redirect(url_for('show_doc_change', doc_change_id=doc_change_id))


@app.route('/delete_notice/<int:row_id>', methods=['POST'])
def delete_notice(row_id):
    """
    Delete a row from notice table.

    :param row_id:
    :return:
    """
    # Check permissions
    if not session['logged_in'] or not session['can_edit_doc']:
        abort(401)

    # Request arguments
    doc_change_id = request.args.get('doc_change_id')

    # Insert data into DB
    db = get_db()
    query = """
                DELETE FROM
                    [notice]
                WHERE
                    [notice].[id] = ?;
                """
    args = [row_id]
    db.execute(query, args)
    db.commit()

    flash('Notice was successfully deleted.')

    return redirect(url_for('show_doc_change', doc_change_id=doc_change_id))


if __name__ == '__main__':
    app.run()
