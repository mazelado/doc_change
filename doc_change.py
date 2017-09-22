# TODO: Improvement - break into modules (views separated)
# TODO: Improvement - use Flask-RESTful to create REST API
# TODO: Try Django to see how it compares

import os
import sys
from datetime import datetime

from flask import Flask, request, render_template, session, g, redirect, url_for, abort, flash
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, login_required, utils
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from passlib.context import CryptContext
from wtforms import StringField, PasswordField, TextAreaField, HiddenField, SelectField, DateField
from wtforms.validators import DataRequired, Length, EqualTo, Email, Optional

# Initialize Flask and set some config values
app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_envvar('CHANGE_FLASK_SETTINGS', silent=True)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = b'\x80\xfd\x11\xef\xad\xe7\x92\x04j1\xcdP\x0b\x0c\xc3\xb8\xf3:\xb6S\xb8o\xb0\xc0'

app.config['SECURITY_PASSWORD_HASH'] = 'pbkdf2_sha512'
app.config['SECURITY_PASSWORD_SALT'] = 'tSFwU8NPMtPK&duND#HMrtEMsQQwQ$#ej58x7yWwpJjdF!hA9x6q5mRET&PU7&2Z'

db_path = os.path.join(app.root_path, 'doc_change_sa.db')
db_uri = 'sqlite:///{}'.format(db_path)
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# SQLAlchemy Models ----------------------------------------------------------------------------------------------------
roles_users = db.Table('roles_users',
                       db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
                       db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))


class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    name = db.Column(db.String(80))
    active = db.Column(db.Boolean())
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))

    def __init__(self, email, password, name, active=True):
        self.email = email
        self.password = password
        self.name = name
        self.active = active

    def __repr__(self):
        return '<User %r>' % self.email


class DocChange(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status_id = db.Column(db.Integer, db.ForeignKey('doc_change_status.id'))
    status = db.relationship('DocChangeStatus')
    submit_date = db.Column(db.Date)
    submit_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    submit_by = db.relationship('User')
    problem_desc = db.Column(db.Text)
    proposal_desc = db.Column(db.Text)
    proposed_implement_date = db.Column(db.Date)
    actual_implement_date = db.Column(db.Date)

    def __init__(self, status_id, submit_date, submit_by_user_id, problem_desc, proposal_desc, proposed_implement_date,
                 actual_implement_date=None):
        self.status_id = status_id
        self.submit_date = submit_date
        self.submit_by_user_id = submit_by_user_id
        self.problem_desc = problem_desc
        self.proposal_desc = proposal_desc
        self.proposed_implement_date = proposed_implement_date
        self.actual_implement_date = actual_implement_date

    def __repr__(self):
        return '<DocChange %r>' % self.id


class DocChangeStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(50))

    def __init__(self, id=1):
        self.id = id

    def __repr__(self):
        return '<DocChangeStatus %r>' % self.status


class AffectedPart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    doc_change_id = db.Column(db.Integer, db.ForeignKey('doc_change.id'))
    doc_change = db.relationship('DocChange')
    part_no = db.Column(db.String(50))
    description = db.Column(db.String(50))
    revision = db.Column(db.String(20))
    routing = db.Column(db.String(50))

    def __init__(self, doc_change_id, part_no, description=None, revision=None, routing=None):
        self.doc_change_id = doc_change_id
        self.part_no = part_no
        self.description = description
        self.revision = revision
        self.routing = routing

    def __repr__(self):
        return '<AffectedPart %r>' % self.id


class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    doc_change_id = db.Column(db.Integer, db.ForeignKey('doc_change.id'))
    doc_change = db.relationship('DocChange')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User')
    status_id = db.Column(db.Integer, db.ForeignKey('request_status.id'))
    status = db.relationship('RequestStatus')
    sent_date = db.Column(db.Date)
    approval_date = db.Column(db.Date)
    notes = db.Column(db.Text)

    def __init__(self, doc_change_id, user_id, status_id, sent_date=None, approval_date=None, notes=None):
        self.doc_change_id = doc_change_id
        self.user_id = user_id
        self.status_id = status_id
        self.sent_date = sent_date
        self.approval_date = approval_date
        self.notes = notes

    def __repr__(self):
        return '<Request %r>' % self.id


class RequestStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(50))

    def __init__(self, status):
        self.status = status

    def __repr__(self):
        return '<RequestStatus %r>' % self.status


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    doc_change_id = db.Column(db.Integer, db.ForeignKey('doc_change.id'))
    doc_change = db.relationship('DocChange')
    doc_type_id = db.Column(db.Integer, db.ForeignKey('doc_type.id'))
    doc_type = db.relationship('DocType')
    notes = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User')
    due_date = db.Column(db.Date)
    sent_date = db.Column(db.Date)
    completed_date = db.Column(db.Date)
    new_revision = db.Column(db.String(20))

    def __init__(self, doc_change_id, doc_type_id, user_id, due_date, notes=None, sent_date=None, completed_date=None,
                 new_revision=None):
        self.doc_change_id = doc_change_id
        self.doc_type_id = doc_type_id
        self.notes = notes
        self.user_id = user_id
        self.due_date = due_date
        self.sent_date = sent_date
        self.completed_date = completed_date
        self.new_revision = new_revision

    def __repr__(self):
        return '<Order %r>' % self.id


class DocType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50))

    def __init__(self, type):
        self.type = type

    def __repr__(self):
        return '<DocType %r>' % self.type


class Notice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    doc_change_id = db.Column(db.Integer, db.ForeignKey('doc_change.id'))
    doc_change = db.relationship('DocChange')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User')
    sent_date = db.Column(db.Date)
    authorize_date = db.Column(db.Date)
    notes = db.Column(db.Text)

    def __init__(self, doc_change_id, user_id, sent_date=None, authorize_date=None, notes=None):
        self.doc_change_id = doc_change_id
        self.user_id = user_id
        self.sent_date = sent_date
        self.authorize_date = authorize_date
        self.notes = notes

    def __repr__(self):
        return '<Notice %r>' % self.id


# Set up Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)


# Logic ----------------------------------------------------------------------------------------------------------------
@app.before_first_request
def before_first_request():
    # Create any database tables that don't exist yet
    db.create_all()

    # Create the Roles 'admin' and 'end-user' unless they already exist
    user_datastore.find_or_create_role(name='admin', description='Administrator')
    user_datastore.find_or_create_role(name='end-user', description='End user')

    # Create two Users for testing purposes -- unless they already exists.
    # In each case, use Flask-Security utility function to encrypt the password.
    encrypted_password = utils.hash_password('password')
    if not user_datastore.get_user('mdaleo@skywayprecision.com'):
        user_datastore.create_user(email='mdaleo@skywayprecision.com', password=encrypted_password)
    if not user_datastore.get_user('admin@skywayprecision.com'):
        user_datastore.create_user(email='admin@skywayprecision.com', password=encrypted_password)

    # Commit any database changes; the User and Roles must exist before we can add a Role to the User
    db.session.commit()

    # Give one User has the "end-user" role, while the other has the "admin" role. (This will have no effect if the
    # Users already have these Roles.) Again, commit any database changes.
    user_datastore.add_role_to_user('mdaleo@skywayprecision.com', 'end-user')
    user_datastore.add_role_to_user('admin@skywayprecision.com', 'admin')
    db.session.commit()


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
            ), 'danger')


def check_doc_change_status(doc_change_id):
    """
    Check document change status and update if possible.

    :param doc_change_id:
    :return: True if updated, False if not updated
    """
    # Constants
    REQUEST_OPEN = 1
    REQUEST_DEFER = 2
    REQUEST_CLOSE = 3
    ORDER = 4
    NOTICE = 5
    COMPLETE = 6

    PENDING = 1
    PROMOTE = 2
    DEFER = 3
    CLOSE = 4

    # Get current status
    doc_change = DocChange.query.filter_by(id=doc_change_id).first()
    updated_status_id = doc_change.status_id

    # If doc change status is Request Open, Defer, or Close, check for possible promotion to Request Open, Defer, or Close, or Order
    if (doc_change.status_id == REQUEST_OPEN) or (doc_change.status_id == REQUEST_DEFER) or (
                doc_change.status_id == REQUEST_CLOSE):
        request_total_count = Request.query.filter_by(doc_change_id=doc_change_id).count()
        request_pending_count = Request.query.filter_by(doc_change_id=doc_change_id, status_id=PENDING).count()
        request_promote_count = Request.query.filter_by(doc_change_id=doc_change_id, status_id=PROMOTE).count()
        request_defer_count = Request.query.filter_by(doc_change_id=doc_change_id, status_id=DEFER).count()
        request_close_count = Request.query.filter_by(doc_change_id=doc_change_id, status_id=CLOSE).count()

        # Check if all request statuses match
        if request_total_count == 0:  # No rows returnd
            return False
        elif request_pending_count == request_total_count:  # They're all Pending
            updated_status_id = REQUEST_OPEN
        elif request_promote_count == request_total_count:  # They're all Promote
            updated_status_id = ORDER
        elif request_defer_count == request_total_count:  # They're all Defer
            updated_status_id = REQUEST_DEFER
        elif request_close_count == request_total_count:  # They're all Close
            updated_status_id = REQUEST_CLOSE
        else:
            return False

    # If status is ORDER, check for possible promotion to NOTICE
    elif doc_change.status_id == ORDER:
        print('DEBUG: Checking orders for doc change {}...'.format(doc_change_id), file=sys.stderr)

        order_total_count = Order.query.filter_by(doc_change_id=doc_change_id).count()
        order_empty_count = Order.query.filter_by(doc_change_id=doc_change_id, new_revision='').count()
        order_null_count = Order.query.filter_by(doc_change_id=doc_change_id, new_revision=None).count()
        order_incomplete_count = order_empty_count + order_null_count

        print('DEBUG: Total orders = {}'.format(order_total_count), file=sys.stderr)
        print('DEBUG: Empty orders = {}'.format(order_empty_count), file=sys.stderr)
        print('DEBUG: Null orders = {}'.format(order_null_count), file=sys.stderr)
        print('DEBUG: Incomplete orders = {}'.format(order_incomplete_count), file=sys.stderr)

        if order_total_count == 0:  # No rows returned
            return False
        elif order_incomplete_count == 0:  # No incomplete rows
            updated_status_id = NOTICE
        else:
            return False

    # If status is NOTICE, check for possible promotion to COMPLETE
    elif doc_change.status_id == NOTICE:
        notice_total_count = Notice.query.filter_by(doc_change_id=doc_change_id).count()
        notice_empty_count = Notice.query.filter_by(doc_change_id=doc_change_id, authorize_date='').count()
        notice_null_count = Notice.query.filter_by(doc_change_id=doc_change_id, authorize_date=None).count()
        notice_incomplete_count = notice_empty_count + notice_null_count

        if notice_total_count == 0:  # No rows returned
            return False
        elif notice_incomplete_count == 0:  # No incomplete rows
            updated_status_id = COMPLETE
        else:
            return False
    else:
        return False

    print('DEBUG: Updated status ID = {}'.format(updated_status_id), file=sys.stderr)

    doc_change.status_id = updated_status_id
    db.session.commit()

    flash('Document Change {} status updated.'.format(doc_change_id), 'success')

    return updated_status_id


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
    email = StringField('Email', validators=[DataRequired()])
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

    if form.validate_on_submit():
        email_from_form = form.email.data
        password_from_form = form.password.data

        # Validate login information
        user = User.query.filter_by(email=email_from_form).first()

        # If user is not found or password does not match
        if user is None or utils.verify_password(password_from_form, user.password) is False:
            flash('Invalid email or password.', 'danger')
        else:
            session['logged_in'] = True
            session['email'] = user.email
            session['name'] = user.name
            session['user_id'] = user.id

            # Get user permissions
            # session['can_view_user'] = user.can_view_user
            # session['can_add_user'] = user.can_add_user
            # session['can_edit_user'] = user.can_edit_user
            # session['can_delete_user'] = user.can_delete_user
            # session['can_view_doc'] = user.can_view_doc
            # session['can_add_doc'] = user.can_add_doc
            # session['can_edit_doc'] = user.can_edit_doc
            # session['can_delete_doc'] = user.can_delete_doc
            # session['can_send_doc'] = user.can_send_doc

            flash('Logged in as {}.'.format(session['name']), 'success')
            return redirect(url_for('show_dashboard'))

    flash_errors(form)
    return redirect(url_for('show_login', error=error))


@app.route('/logout/')
@login_required
def do_logout():
    """
    Log the user out of the system.

    :return:
    """
    name = session['name']

    # Clear session variables
    session.pop('logged_in', None)
    session.pop('email', None)
    session.pop('name', None)
    session.pop('user_id', None)
    # session.pop('can_view_user', None)
    # session.pop('can_add_user', None)
    # session.pop('can_edit_user', None)
    # session.pop('can_delete_user', None)
    # session.pop('can_view_doc', None)
    # session.pop('can_add_doc', None)
    # session.pop('can_edit_doc', None)
    # session.pop('can_delete_doc', None)
    # session.pop('can_send_doc', None)

    flash('{} logged out.'.format(name), 'info')
    return redirect(url_for('show_start'))


class RegistrationForm(FlaskForm):
    email = StringField('Email Address', validators=[DataRequired(), Length(min=6, max=255), Email()])
    name = StringField('Name', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password',
                             validators=[DataRequired(), EqualTo('confirm', message='Passwords do not match.'),
                                         Length(min=8, max=32)])
    confirm = PasswordField('Confirm Password', validators=[DataRequired()])


@app.route('/register/')
@login_required
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
@login_required
def insert_user():
    """
    Insert a row into the users table.

    :return:
    """
    error = None

    # CSRF is disabled because it prevented this from working and I couldn't figure out why it was missing
    # TODO: Figure out why CSRF token is missing and re-enable
    form = RegistrationForm(request.form, csrf_enabled=False)

    if form.validate_on_submit():
        new_user = User(form.email.data, utils.hash_password(form.password.data), form.email.data, form.name.data)

        # Check if user already exists
        existing_user = User.query.filter_by(email=form.email.data).first()

        if existing_user is not None:
            flash('Invalid email.', 'danger')
            return render_template('register_user.html', form=form, error=error)
        else:
            # Add user to database
            db.session.add(new_user)
            db.session.commit()

            flash('New user \'{}\' was successfully added.'.format(new_user.email), 'success')
            return redirect(url_for('show_start'))

    return render_template('register_user.html', form=form, error=error)


@app.route('/edit_user/')
@login_required
def show_edit_user():
    """
    Show form to edit user information.

    :return:
    """
    error = None

    # CSRF is disabled because it prevented this from working and I couldn't figure out why it was missing
    # TODO: Figure out why CSRF token is missing and re-enable
    form = RegistrationForm(request.form, csrf_enabled=False)

    user_to_show = User.query.filter_by(id=session['user_id']).first()
    form.email.data = user_to_show.email
    form.name.data = user_to_show.name

    return render_template('edit_profile.html', error=error, form=form)


@app.route('/update_user/', methods=['POST'])
@login_required
def update_user():
    """
    Edit user profile.
    """
    error = None

    # CSRF is disabled because it prevented this from working and I couldn't figure out why it was missing
    # TODO: Figure out why CSRF token is missing and re-enable
    form = RegistrationForm(request.form, csrf_enabled=False)

    if form.validate_on_submit():
        user_to_update = User.query.filter_by(id=session['user_id']).first()

        user_to_update.email = form.email.data
        user_to_update.name = form.name.data
        user_to_update.password = utils.hash_password(form.password.data)

        db.session.commit()

        flash('User \'{}\' successfully updated.'.format(user_to_update.email), 'success')

    flash_errors(form)
    return redirect(url_for('show_edit_user', error=error))


@app.route('/edit_all_users/')
@login_required
def show_edit_all_users():
    """
    Show form to edit all user information.

    :return:
    """
    error = None

    # CSRF is disabled because it prevented this from working and I couldn't figure out why it was missing
    # TODO: Figure out why CSRF token is missing and re-enable
    form = RegistrationForm(request.form, csrf_enabled=False)

    users_to_show = User.query.all()

    return render_template('edit_all_users.html', error=error, form=form)


@app.route('/dashboard/')
@login_required
def show_dashboard():
    """
    Display user dashboard.

    :return:
    """

    error = None

    # Get Incomplete Requests
    query = """
            SELECT [doc_change].[id], 
                   [doc_change].[problem_desc], 
                   [doc_change].[proposal_desc], 
                   [doc_change].[proposed_implement_date]
            FROM   [doc_change]
                   LEFT JOIN [request] ON [request].[doc_change_id] = [doc_change].[id]
                   LEFT JOIN [affected_part] ON [affected_part].[doc_change_id] = [doc_change].[id]
            WHERE  ([doc_change].[status_id] = 1)
                   AND ([doc_change].[submit_by_user_id] = :doc_change_submit_by_user_id)
                   AND (([request].[id] ISNULL)
                   OR  ([affected_part].[id] ISNULL));
            """
    args = {'doc_change_submit_by_user_id': session['user_id']}
    inc_req_results = db.session.execute(query, args)

    # Get Pending Requests
    query = """
            SELECT [doc_change].[id] AS [doc_change_id], 
                   [doc_change].[submit_date] AS [doc_change_submit_date], 
                   [doc_change].[problem_desc] AS [doc_change_problem_desc], 
                   [doc_change].[proposal_desc] AS [doc_change_proposal_desc], 
                   GROUP_CONCAT ([affected_part].[part_no], ", ") AS [part_nos]
            FROM   [doc_change]
                   JOIN [request] ON [doc_change].[id] = [request].[doc_change_id]
                   JOIN [affected_part] ON [doc_change].[id] = [affected_part].[doc_change_id]
            WHERE  [doc_change].[status_id] = :doc_change_status_id
                   AND [request].[status_id] = :request_status_id
                   AND [request].[user_id] = :request_user_id
            GROUP  BY [doc_change].[id]
            ORDER BY [doc_change].[id];            
            """
    args = {'doc_change_status_id': 1, 'request_status_id': 1, 'request_user_id': session['user_id']}
    req_results = db.session.execute(query, args)

    # Get Incomplete Orders

    # Get Pending Orders
    query = """
            SELECT [doc_change].[id] AS [doc_change_id], 
                   [doc_type].[type] AS [doc_type_type], 
                   [order].[notes] AS [order_notes], 
                   [order].[due_date] AS [order_due_date]
            FROM   [doc_change]
                   JOIN [order] ON [doc_change].[id] = [order].[doc_change_id]
                   JOIN [doc_type] ON [doc_type].[id] = [order].[doc_type_id]
            WHERE  [doc_change].[status_id] = :doc_change_status_id
                   AND [order].[user_id] = :order_user_id
                   AND (("order".[completed_date] = "")
                   OR  ("order".[completed_date] ISNULL))
            ORDER BY [doc_change].[id];            
            """
    args = {'doc_change_status_id': 4, 'order_user_id': session['user_id']}
    ord_results = db.session.execute(query, args)

    # Get Incomplete Notices

    # Get Pending Notices
    query = """
            SELECT [doc_change].[id] AS [doc_change_id], 
                   [doc_change].[proposed_implement_date] AS [doc_change_proposed_implement_date]
            FROM   [doc_change]
                   JOIN [notice] ON [doc_change].[id] = [notice].[doc_change_id]
            WHERE  [doc_change].[status_id] = :doc_change_status_id
                   AND [notice].[user_id] = :notice_user_id
                   AND (([notice].[authorize_date] = "")
                   OR  ([notice].[authorize_date] ISNULL))
            ORDER BY [doc_change].[id];
            """
    args = {'doc_change_status_id': 5, 'notice_user_id': session['user_id']}
    ntc_results = db.session.execute(query, args)

    return render_template('dashboard.html', error=error, inc_req_results=inc_req_results, req_results=req_results,
                           ord_results=ord_results, ntc_results=ntc_results)


@app.route('/dashboard_as_admin/')
@login_required
def show_dashboard_as_admin():
    """
    Display Administrator dashboard.

    :return:
    """
    return 'Administrator Dashboard'


@app.route('/doc_change/all/')
@login_required
def show_all_doc_changes():
    """
    Display all document changes in a filterable list.
    """

    # TODO: Change table so that it can sort id, submit_date by value, not alphabetical
    # https://github.com/wenzhixin/bootstrap-table/issues/821

    error = None

    # Get all Document Changes
    query = """
            SELECT [doc_change].[id] AS [doc_change_id],
                   [doc_change_status].[status] AS [doc_change_status_status],
                   [doc_change].[submit_date] AS [doc_change_submit_date], 
                   [doc_change].[problem_desc] AS [doc_change_problem_desc], 
                   [doc_change].[proposal_desc] AS [doc_change_proposal_desc], 
                   GROUP_CONCAT ([affected_part].[part_no], ", ") AS [part_nos]
            FROM   [doc_change]
                   JOIN [doc_change_status] ON [doc_change].[status_id] = [doc_change_status].[id]
                   JOIN [affected_part] ON [doc_change].[id] = [affected_part].[doc_change_id]
            GROUP  BY [doc_change].[id];            
            """
    args = {'doc_change_status_id': 1, 'request_status_id': 1, 'request_user_id': session['user_id']}
    rows = db.session.execute(query, args)

    return render_template('view_all.html', error=error, rows=rows)


class DocChangeForm(FlaskForm):
    id = HiddenField('Row ID')
    status_id = SelectField('Status', coerce=int, render_kw={'disabled': True})
    status = StringField('Status', render_kw={'readonly': True})
    submit_by_user_id = SelectField('Submit By User ID', coerce=int, render_kw={'disabled': True})
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
    user_id = SelectField('Stakeholder', coerce=int)
    name = StringField('Name', render_kw={'readonly': True})
    email = StringField('Email Address', render_kw={'readonly': True})
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
    user_id = SelectField('Responsible', coerce=int)
    name = StringField('Name', render_kw={'readonly': True})
    email = StringField('Email Address', render_kw={'readonly': True})
    due_date = StringField('Due Date', validators=[DataRequired()])
    sent_date = StringField('Sent Date')
    completed_date = StringField('Completed Date')
    new_revision = StringField('New Revision')


class DocChangeNoticeForm(FlaskForm):
    id = HiddenField('Row ID')
    doc_change_id = HiddenField('Document Change ID')
    user_id = SelectField('Authorize By', coerce=int)
    name = StringField('Name', render_kw={'readonly': True})
    email = StringField('Email Address', render_kw={'readonly': True})
    sent_date = StringField('Sent Date', validators=[Optional()])
    authorize_date = StringField('Authorized Date', validators=[Optional()])
    notes = TextAreaField('Notes')


@app.route('/doc_change/')
@app.route('/doc_change/<int:doc_change_id>/')
@login_required
def show_doc_change(doc_change_id=0):
    """
    View a Document Change from the DB

    :param doc_change_id:
    :return:
    """
    error = None

    # Initialize forms
    doc_change_form = DocChangeForm(request.form, csrf_enabled=False)
    doc_change_affected_parts_form = DocChangeAffectedPartsForm(request.form, csrf_enabled=False,
                                                                doc_change_id=doc_change_id)
    doc_change_request_form = DocChangeRequestForm(request.form, csrf_enabled=False, doc_change_id=doc_change_id)
    doc_change_order_form = DocChangeOrderForm(request.form, csrf_enabled=False, doc_change_id=doc_change_id)
    doc_change_notice_form = DocChangeNoticeForm(request.form, csrf_enabled=False, doc_change_id=doc_change_id)

    # Get Document Change Statuses from DB
    doc_change_statuses = DocChangeStatus.query.order_by(DocChangeStatus.id).all()
    doc_change_form.status_id.choices = [(row.id, row.status) for row in doc_change_statuses]

    # Get Users from DB
    users = User.query.order_by(User.name).all()
    doc_change_form.submit_by_user_id.choices = [(row.id, '{} ({})'.format(row.name, row.email)) for row in users]
    doc_change_request_form.user_id.choices = [(row.id, '{} ({})'.format(row.name, row.email)) for row in users]
    doc_change_order_form.user_id.choices = [(row.id, '{} ({})'.format(row.name, row.email)) for row in users]
    doc_change_notice_form.user_id.choices = [(row.id, '{} ({})'.format(row.name, row.email)) for row in users]

    # Get Request Statuses from DB
    request_statuses = RequestStatus.query.order_by(RequestStatus.id).all()
    doc_change_request_form.status_id.choices = [(row.id, row.status) for row in request_statuses]

    # Get Document Types from DB
    order_document_types = DocType.query.order_by(DocType.type).all()
    doc_change_order_form.document_type_id.choices = [(row.id, row.type) for row in order_document_types]

    if doc_change_id == 0:  # New Doc Change
        return render_template('doc_change.html', error=error, doc_change_id=doc_change_id,
                               doc_change_form=doc_change_form, doc_change_request_form=doc_change_request_form,
                               doc_change_affected_parts_form=doc_change_affected_parts_form)
    else:  # Existing Doc Change
        # Get Document Change data
        doc_change_row = DocChange.query.filter_by(id=doc_change_id).first()

        # Check that records exist in DB
        if not doc_change_row:
            redirect(url_for('show_doc_change', doc_change_id=0))

        # Get Affected Parts
        affected_parts_rows = AffectedPart.query.filter_by(doc_change_id=doc_change_id).all()

        # Get Requests
        request_rows = Request.query.filter_by(doc_change_id=doc_change_id) \
            .join(User) \
            .add_columns(User.name, User.email) \
            .all()

        # Get Orders
        order_rows = Order.query.filter_by(doc_change_id=doc_change_id) \
            .join(DocType) \
            .join(User) \
            .add_columns(DocType.type, User.name, User.email) \
            .all()

        # Get Notices from DB
        notice_rows = Notice.query.filter_by(doc_change_id=doc_change_id) \
            .join(User) \
            .add_columns(User.name, User.email) \
            .all()

        # Populate form with data
        doc_change_form.status_id.data = doc_change_row.status_id
        doc_change_form.submit_date.data = doc_change_row.submit_date
        doc_change_form.submit_by_user_id.data = doc_change_row.submit_by.id
        doc_change_form.problem_desc.data = doc_change_row.problem_desc
        doc_change_form.proposal_desc.data = doc_change_row.proposal_desc
        doc_change_form.proposed_implement_date.data = doc_change_row.proposed_implement_date
        doc_change_form.actual_implement_date.data = doc_change_row.actual_implement_date

        flash_errors(doc_change_form)
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
@login_required
def insert_doc_change():
    """
    Insert a new Document Change into the DB

    :return:
    """
    error = None

    # Initialize forms
    doc_change_form = DocChangeForm(request.form, csrf_enabled=False)

    # Get Document Change Statuses from DB
    doc_change_statuses = DocChangeStatus.query.order_by(DocChangeStatus.id).all()
    doc_change_form.status_id.choices = [(row.id, row.status) for row in doc_change_statuses]

    # Get Users from DB
    users = User.query.order_by(User.name).all()
    doc_change_form.submit_by_user_id.choices = [(row.id, '{} ({})'.format(row.name, row.email)) for row in users]
    doc_change_form.submit_by_user_id.data = session['user_id']

    if doc_change_form.validate_on_submit():
        # Save data to variables
        doc_change_form.status_id.data = 1
        new_doc_change = DocChange(doc_change_form.status_id.data,
                                   datetime.today(),
                                   session['user_id'],
                                   doc_change_form.problem_desc.data,
                                   doc_change_form.proposal_desc.data,
                                   datetime.strptime(doc_change_form.proposed_implement_date.data, '%Y-%m-%d'))

        # Add doc change to database
        db.session.add(new_doc_change)
        db.session.commit()

        # Store ID of last row added
        doc_change_id = new_doc_change.id

        flash('Document Change {} was successfully added.'.format(doc_change_id), 'success')

    flash_errors(doc_change_form)
    return redirect(url_for('show_doc_change', error=error, doc_change_id=doc_change_id))


@app.route('/update_doc_change/<int:doc_change_id>/', methods=['POST'])
@login_required
def update_doc_change(doc_change_id):
    """
    Update a row in doc_change table.

    :param doc_change_id:
    :return:
    """
    error = None

    # Initialize forms
    doc_change_form = DocChangeForm(request.form, csrf_enabled=False)

    # Get Document Change Statuses from DB
    doc_change_statuses = DocChangeStatus.query.order_by(DocChangeStatus.id).all()
    doc_change_form.status_id.choices = [(row.id, row.status) for row in doc_change_statuses]
    doc_change_form.status_id.data = 1

    # Get Users from DB
    users = User.query.order_by(User.name).all()
    doc_change_form.submit_by_user_id.choices = [(row.id, '{} ({})'.format(row.name, row.email)) for row in users]
    doc_change_form.submit_by_user_id.data = session['user_id']

    if doc_change_form.validate_on_submit():
        # Update doc change
        doc_change = DocChange.query.filter_by(id=doc_change_id).first()
        doc_change.problem_desc = doc_change_form.problem_desc.data
        doc_change.proposal_desc = doc_change_form.proposal_desc.data
        doc_change.proposed_implement_date = datetime.strptime(doc_change_form.proposed_implement_date.data, '%Y-%m-%d')

        db.session.commit()

        flash('Document Change {} was successfully updated.'.format(doc_change_id), 'success')

    flash_errors(doc_change_form)
    return redirect(url_for('show_doc_change', error=error, doc_change_id=doc_change_id))


@app.route('/add_affected_part_no/', methods=['POST'])
@login_required
def insert_affected_part_no():
    """
    Insert a row into affected_part_no table.

    :return:
    """
    error = None

    # Initialize forms
    doc_change_affected_parts_form = DocChangeAffectedPartsForm(request.form, csrf_enabled=False)
    doc_change_id = doc_change_affected_parts_form.doc_change_id.data

    if doc_change_affected_parts_form.validate_on_submit():
        # Save all form data to variables
        part_no = doc_change_affected_parts_form.part_no.data
        new_affected_part = AffectedPart(doc_change_id,
                                         part_no,
                                         doc_change_affected_parts_form.desc.data,
                                         doc_change_affected_parts_form.rev.data,
                                         doc_change_affected_parts_form.routing.data)

        # Insert data into DB
        db.session.add(new_affected_part)
        db.session.commit()

        flash('Part number \'{}\' was successfully added.'.format(part_no), 'success')

    flash_errors(doc_change_affected_parts_form)
    return redirect(url_for('show_doc_change', error=error, doc_change_id=doc_change_id))


@app.route('/edit_affected_part_no/', methods=['POST'])
@login_required
def update_affected_part_no():
    """
    Update a row in affected_part_no table.

    :return:
    """
    error = None

    # Initialize forms
    doc_change_affected_parts_form = DocChangeAffectedPartsForm(request.form, csrf_enabled=False)
    doc_change_id = doc_change_affected_parts_form.doc_change_id.data

    if doc_change_affected_parts_form.validate_on_submit():
        # Save all form data to variables
        affected_part = AffectedPart.query.filter_by(id=doc_change_affected_parts_form.id.data).first()
        part_no = doc_change_affected_parts_form.part_no.data
        affected_part.part_no = part_no
        affected_part.description = doc_change_affected_parts_form.desc.data
        affected_part.revision = doc_change_affected_parts_form.rev.data
        affected_part.routing = doc_change_affected_parts_form.routing.data

        # Update data in DB
        db.session.commit()

        flash('Part number \'{}\' was successfully updated.'.format(part_no), 'success')

    flash_errors(doc_change_affected_parts_form)
    return redirect(url_for('show_doc_change', error=error, doc_change_id=doc_change_id))


@app.route('/delete_affected_part_no/<int:row_id>/', methods=['POST'])
@login_required
def delete_affected_part_no(row_id):
    """
    Delete a row from affected_part_no table.

    :param row_id:
    :return:
    """
    # Request arguments
    doc_change_id = request.args.get('doc_change_id')

    # Delete data from DB
    affected_part = AffectedPart.query.filter_by(id=row_id).first()
    part_no = affected_part.part_no

    db.session.delete(affected_part)
    db.session.commit()

    flash('Part \'{}\' was successfully deleted.'.format(part_no), 'success')

    return redirect(url_for('show_doc_change', doc_change_id=doc_change_id))


@app.route('/insert_request/', methods=['POST'])
@login_required
def insert_request():
    """
    Insert a row into requests table.

    :return:
    """
    error = None

    # Initialize forms
    doc_change_request_form = DocChangeRequestForm(request.form, csrf_enabled=False)
    doc_change_id = doc_change_request_form.doc_change_id.data

    # Get Request Statuses from DB
    request_statuses = RequestStatus.query.order_by(RequestStatus.id).all()
    doc_change_request_form.status_id.choices = [(row.id, row.status) for row in request_statuses]

    # Get Users from DB
    users = User.query.order_by(User.name).all()
    doc_change_request_form.user_id.choices = [(row.id, '{} ({})'.format(row.name, row.email)) for row in users]

    if doc_change_request_form.validate_on_submit():
        # Save all form data to variables
        new_request = Request(doc_change_id,
                              doc_change_request_form.user_id.data,
                              doc_change_request_form.status_id.data,
                              notes=doc_change_request_form.notes.data)

        # Insert data into DB
        db.session.add(new_request)
        db.session.commit()

        flash('Request stakeholder {} was successfully added.'.format(new_request.user.name), 'success')

    flash_errors(doc_change_request_form)
    return redirect(url_for('show_doc_change', error=error, doc_change_id=doc_change_id))


@app.route('/update_request/', methods=['POST'])
@login_required
def update_request():
    """
    Update a row in requests table.

    :return:
    """
    error = None

    # Initialize forms
    doc_change_request_form = DocChangeRequestForm(request.form, csrf_enabled=False)
    doc_change_id = doc_change_request_form.doc_change_id.data

    # Get Request Statuses from DB
    request_statuses = RequestStatus.query.order_by(RequestStatus.id).all()
    doc_change_request_form.status_id.choices = [(row.id, row.status) for row in request_statuses]

    # Get Users from DB
    users = User.query.order_by(User.name).all()
    doc_change_request_form.user_id.choices = [(row.id, '{} ({})'.format(row.name, row.email)) for row in users]

    if doc_change_request_form.validate_on_submit():
        # Save all form data to variables
        updated_request = Request.query.filter_by(id=doc_change_request_form.id.data).first()
        updated_request.user_id = doc_change_request_form.user_id.data
        updated_request.status_id = doc_change_request_form.status_id.data
        updated_request.notes = doc_change_request_form.notes.data

        if updated_request.status_id > 1:
            updated_request.approval_date = datetime.today()
        else:
            updated_request.approval_date = None

        # Insert data into DB
        db.session.commit()

        flash('Request stakeholder {} was successfully updated.'.format(updated_request.user.name), 'success')

        check_doc_change_status(doc_change_id)

    flash_errors(doc_change_request_form)
    return redirect(url_for('show_doc_change', error=error, doc_change_id=doc_change_id))


@app.route('/delete_request/<int:row_id>', methods=['POST'])
@login_required
def delete_request(row_id):
    """
    Delete a row from requests table.

    :param row_id:
    :return:
    """
    # Request arguments
    doc_change_id = request.args.get('doc_change_id')

    # Delete data from DB
    request_to_delete = Request.query.filter_by(id=row_id).first()
    request_name = request_to_delete.user.name

    db.session.delete(request_to_delete)
    db.session.commit()

    flash('Request stakeholder {} was successfully deleted.'.format(request_name), 'success')

    check_doc_change_status(doc_change_id)

    return redirect(url_for('show_doc_change', doc_change_id=doc_change_id))


@app.route('/insert_order/', methods=['POST'])
@login_required
def insert_order():
    """
    Insert a row into order table.

    :return:
    """
    error = None

    # Initialize forms
    doc_change_order_form = DocChangeOrderForm(request.form, csrf_enabled=False)
    doc_change_id = doc_change_order_form.doc_change_id.data

    # Get Document Types from DB
    order_document_types = DocType.query.order_by(DocType.type).all()
    doc_change_order_form.document_type_id.choices = [(row.id, row.type) for row in order_document_types]

    # Get Users from DB
    users = User.query.order_by(User.name).all()
    doc_change_order_form.user_id.choices = [(row.id, '{} ({})'.format(row.name, row.email)) for row in users]

    if doc_change_order_form.validate_on_submit():
        # Save all form data to variables
        order_to_insert = Order(doc_change_id,
                                doc_change_order_form.document_type_id.data,
                                doc_change_order_form.user_id.data,
                                datetime.strptime(doc_change_order_form.due_date.data, '%Y-%m-%d'),
                                doc_change_order_form.new_revision.data)

        # Insert data into DB
        db.session.add(order_to_insert)
        db.session.commit()

        flash('Order was successfully added.', 'success')

    flash_errors(doc_change_order_form)
    return redirect(url_for('show_doc_change', error=error, doc_change_id=doc_change_id))


@app.route('/update_order/', methods=['POST'])
@login_required
def update_order():
    """
    Update a row in order table.

    :return:
    """
    error = None

    # Initialize forms
    doc_change_order_form = DocChangeOrderForm(request.form, csrf_enabled=False)
    doc_change_id = doc_change_order_form.doc_change_id.data

    # Get Document Types from DB
    order_document_types = DocType.query.order_by(DocType.type).all()
    doc_change_order_form.document_type_id.choices = [(row.id, row.type) for row in order_document_types]

    # Get Users from DB
    users = User.query.order_by(User.name).all()
    doc_change_order_form.user_id.choices = [(row.id, '{} ({})'.format(row.name, row.email)) for row in users]

    if doc_change_order_form.validate_on_submit():
        # Save all form data to variables
        order_to_update = Order.query.filter_by(id=doc_change_order_form.id.data).first()
        order_to_update.doc_type_id = doc_change_order_form.document_type_id.data
        order_to_update.user_id = doc_change_order_form.user_id.data
        order_to_update.notes = doc_change_order_form.notes.data
        order_to_update.due_date = datetime.strptime(doc_change_order_form.due_date.data, '%Y-%m-%d')
        order_to_update.new_revision = doc_change_order_form.new_revision.data
        if (order_to_update.new_revision != '') and (order_to_update.new_revision is not None):
            order_to_update.completed_date = datetime.today()
        else:
            order_to_update.completed_date = None

        # Update data in DB
        db.session.commit()

        flash('Order was successfully updated.', 'success')

        check_doc_change_status(doc_change_id)

    flash_errors(doc_change_order_form)
    return redirect(url_for('show_doc_change', doc_change_id=doc_change_id))


@app.route('/delete_order/<int:row_id>', methods=['POST'])
@login_required
def delete_order(row_id):
    """
    Delete a row from order table.

    :param row_id:
    :return:
    """
    # Request arguments
    doc_change_id = request.args.get('doc_change_id')

    # Insert data into DB
    order_to_delete = Order.query.filter_by(id=row_id).first()

    db.session.delete(order_to_delete)
    db.session.commit()

    flash('Order was successfully deleted.', 'success')

    check_doc_change_status(doc_change_id)

    return redirect(url_for('show_doc_change', doc_change_id=doc_change_id))


@app.route('/insert_notice/', methods=['POST'])
@login_required
def insert_notice():
    """
    Insert a row into notice table.

    :return:
    """
    error = None

    # Initialize forms
    doc_change_notice_form = DocChangeNoticeForm(request.form, csrf_enabled=False)
    doc_change_id = doc_change_notice_form.doc_change_id.data

    # Get Users from DB
    users = User.query.order_by(User.name).all()
    doc_change_notice_form.user_id.choices = [(row.id, '{} ({})'.format(row.name, row.email)) for row in users]

    if doc_change_notice_form.validate_on_submit():
        # Save all form data to variables
        notice_to_insert = Notice(doc_change_id, doc_change_notice_form.user_id.data,
                                  notes=doc_change_notice_form.notes.data)

        # Insert data into DB
        db.session.add(notice_to_insert)
        db.session.commit()

        flash('Notice was successfully added.', 'success')

    flash_errors(doc_change_notice_form)
    return redirect(url_for('show_doc_change', error=error, doc_change_id=doc_change_id))


@app.route('/update_notice/', methods=['POST'])
@login_required
def update_notice():
    """
    Update a row in notice table.

    :return:
    """
    error = None

    # Initialize form
    doc_change_notice_form = DocChangeNoticeForm(request.form, csrf_enabled=False)
    doc_change_id = doc_change_notice_form.doc_change_id.data

    # Get Users from DB
    users = User.query.order_by(User.name).all()
    doc_change_notice_form.user_id.choices = [(row.id, '{} ({})'.format(row.name, row.email)) for row in users]

    if doc_change_notice_form.validate_on_submit():
        # Save all form data to variables
        notice_to_update = Notice.query.filter_by(id=doc_change_notice_form.id.data).first()
        notice_to_update.user_id = doc_change_notice_form.user_id.data
        try:
            notice_to_update.authorize_date = datetime.strptime(doc_change_notice_form.authorize_date.data, '%Y-%m-%d')
        except ValueError:
            pass
        notice_to_update.notes = doc_change_notice_form.notes.data

        # Update data in DB
        db.session.commit()

        flash('Notice was successfully updated.', 'success')

        check_doc_change_status(doc_change_id)

    flash_errors(doc_change_notice_form)
    return redirect(url_for('show_doc_change', error=error, doc_change_id=doc_change_id))


@app.route('/delete_notice/<int:row_id>', methods=['POST'])
@login_required
def delete_notice(row_id):
    """
    Delete a row from notice table.

    :param row_id:
    :return:
    """
    error = None

    # Request arguments
    doc_change_id = request.args.get('doc_change_id')

    # Insert data into DB
    notice_to_delete = Notice.query.filter_by(id=row_id).first()
    db.session.delete(notice_to_delete)
    db.session.commit()

    flash('Notice was successfully deleted.', 'success')

    check_doc_change_status(doc_change_id)

    return redirect(url_for('show_doc_change', doc_change_id=doc_change_id))


@app.route('/copy_request_to_notice/<int:doc_change_id>', methods=['POST'])
@login_required
def copy_request_to_notice(doc_change_id):
    """
    Copy all stakeholders from request to notice.

    :param doc_change_id:
    :return:
    """
    query = """
            INSERT INTO [notice]
                ([doc_change_id], 
                [user_id])
                SELECT [doc_change_id], 
                   [user_id]
            FROM   [request]
            WHERE  [doc_change_id] = :doc_change_id;
            """
    args = {'doc_change_id': doc_change_id}
    db.session.execute(query, args)
    db.session.commit()

    flash('Request stakeholders successfully copied to Notice.', 'success')

    return redirect(url_for('show_doc_change', doc_change_id=doc_change_id))


if __name__ == '__main__':
    app.run()
