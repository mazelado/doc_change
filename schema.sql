DROP TABLE IF EXISTS 'users';

CREATE TABLE 'users'(
    [id] INTEGER PRIMARY KEY AUTOINCREMENT,
    [username] TEXT NOT NULL,
    [password] TEXT NOT NULL,
    [first_name] TEXT NOT NULL,
    [last_name] TEXT NOT NULL,
    [email] TEXT NOT NULL,
    [can_view_user] INTEGER DEFAULT 0,
    [can_add_user] INTEGER DEFAULT 0,
    [can_edit_user] INTEGER DEFAULT 0,
    [can_delete_user] INTEGER DEFAULT 0,
    [can_view_doc] INTEGER DEFAULT 0,
    [can_add_doc] INTEGER DEFAULT 0,
    [can_edit_doc] INTEGER DEFAULT 0,
    [can_delete_doc] INTEGER DEFAULT 0,
    [can_send_doc] INTEGER DEFAULT 0);

INSERT INTO 'users'
    ('username',
    'password',
    'first_name',
    'last_name',
    'email',
    'can_view_user',
    'can_add_user',
    'can_edit_user',
    'can_delete_user',
    'can_view_doc',
    'can_add_doc',
    'can_edit_doc',
    'can_delete_doc',
    'can_send_doc')
    VALUES ('admin', '$pbkdf2-sha256$29000$.1.L8V4rxdj7v/deKwVgbA$gkP4diAMFV1NLkrdkyBYlj9w6B/BstDI2DABLnpT8e4', 'Administrator', '', 'mdaleo@skywayprecision.com', 1, 1, 1, 1, 1, 1, 1, 1, 1);

DROP TABLE IF EXISTS 'doc_changes';

CREATE TABLE 'doc_changes'(
    [id] INTEGER PRIMARY KEY AUTOINCREMENT,
    [status_id] INTEGER NOT NULL,
    [submit_date] TEXT NOT NULL,
    [submit_by] TEXT NOT NULL,
    [problem_desc] TEXT NOT NULL,
    [proposal_desc] TEXT NOT NULL,
    [proposed_implement_date] TEXT NOT NULL,
    [actual_implement_date] TEXT);

DROP TABLE IF EXISTS 'doc_change_status';

CREATE TABLE 'doc_change_status'(
    [id] INTEGER PRIMARY KEY,
    [status] TEXT NOT NULL);

INSERT INTO 'doc_change_status'
    ('id',
    'status')
    VALUES (1, "Request (Open)");

INSERT INTO 'doc_change_status'
    ('id',
    'status')
    VALUES (2, "Request (Deferred)");

INSERT INTO 'doc_change_status'
    ('id',
    'status')
    VALUES (3, "Request (Closed)");

INSERT INTO 'doc_change_status'
    ('id',
    'status')
    VALUES (4, "Order");

INSERT INTO 'doc_change_status'
    ('id',
    'status')
    VALUES (5, "Notice");

INSERT INTO 'doc_change_status'
    ('id',
    'status')
    VALUES (6, "Completed");

DROP TABLE IF EXISTS 'affected_parts';

CREATE TABLE 'affected_parts'(
    [id] INTEGER PRIMARY KEY AUTOINCREMENT,
    [doc_change_id] INTEGER NOT NULL,
    [part_no] TEXT NOT NULL,
    [revision] TEXT,
    [routing] TEXT,
    [description] TEXT);

DROP TABLE IF EXISTS 'request';

CREATE TABLE 'request'(
    [id] INTEGER PRIMARY KEY AUTOINCREMENT,
    [doc_change_id] INTEGER NOT NULL,
    [stakeholder_name] TEXT NOT NULL,
    [stakeholder_email] TEXT,
    [status_id] INTEGER NOT NULL,
    [sent_date] TEXT,
    [approval_date] TEXT,
    [notes] TEXT);

DROP TABLE IF EXISTS 'request_status';

CREATE TABLE 'request_status'(
    [id] INTEGER PRIMARY KEY,
    [status] TEXT NOT NULL);

INSERT INTO 'request_status'
    ('id',
    'status')
    VALUES (1, "Pending");

INSERT INTO 'request_status'
    ('id',
    'status')
    VALUES (2, "Promote");

INSERT INTO 'request_status'
    ('id',
    'status')
    VALUES (3, "Defer");

INSERT INTO 'request_status'
    ('id',
    'status')
    VALUES (4, "Close");

DROP TABLE IF EXISTS 'document_types';

CREATE TABLE 'document_types'(
    [id] INTEGER PRIMARY KEY AUTOINCREMENT,
    [document_name] TEXT NOT NULL);

INSERT INTO 'document_types'
    ('id',
    'document_name')
    VALUES (1, "Customer Print");

INSERT INTO 'document_types'
    ('id',
    'document_name')
    VALUES (2, "Balloon Print");

INSERT INTO 'document_types'
    ('id',
    'document_name')
    VALUES (3, "ERP Records");

INSERT INTO 'document_types'
    ('id',
    'document_name')
    VALUES (4, "Process Flowchart");

INSERT INTO 'document_types'
    ('id',
    'document_name')
    VALUES (5, "PFMEA");

INSERT INTO 'document_types'
    ('id',
    'document_name')
    VALUES (6, "Setup Instructions");

INSERT INTO 'document_types'
    ('id',
    'document_name')
    VALUES (7, "CNC Programs");

INSERT INTO 'document_types'
    ('id',
    'document_name')
    VALUES (8, "Control Plan");

INSERT INTO 'document_types'
    ('id',
    'document_name')
    VALUES (9, "Process Prints");

INSERT INTO 'document_types'
    ('id',
    'document_name')
    VALUES (10, "Gage Setup Instructions");

INSERT INTO 'document_types'
    ('id',
    'document_name')
    VALUES (11, "Inspection Records");

INSERT INTO 'document_types'
    ('id',
    'document_name')
    VALUES (12, "SPC Records");

INSERT INTO 'document_types'
    ('id',
    'document_name')
    VALUES (13, "CMM Programs");

INSERT INTO 'document_types'
    ('id',
    'document_name')
    VALUES (14, "Gage R&Rs");

INSERT INTO 'document_types'
    ('id',
    'document_name')
    VALUES (15, "Training Plan");

INSERT INTO 'document_types'
    ('id',
    'document_name')
    VALUES (16, "Implementation Plan");

INSERT INTO 'document_types'
    ('id',
    'document_name')
    VALUES (17, "Inspection Records (Variat)");

DROP TABLE IF EXISTS 'order';

CREATE TABLE 'order'(
    [id] INTEGER PRIMARY KEY AUTOINCREMENT,
    [doc_change_id] INTEGER NOT NULL,
    [document_type_id] INTEGER NOT NULL,
    [notes] TEXT,
    [responsible_name] TEXT NOT NULL,
    [responsible_email] TEXT NOT NULL,
    [due_date] TEXT NOT NULL,
    [sent_date] TEXT,
    [completed_date] TEXT,
    [new_revision] TEXT);

DROP TABLE IF EXISTS 'notice';

CREATE TABLE 'notice'(
    [id] INTEGER PRIMARY KEY AUTOINCREMENT,
    [doc_change_id] INTEGER NOT NULL,
    [authorize_name] TEXT NOT NULL,
    [authorize_email] TEXT NOT NULL,
    [sent_date] TEXT,
    [authorize_date] TEXT,
    [notes] TEXT);
