# doc_change
Document control system. Controls the flow of Engineering Change Orders through multiple people in the organization. Sends email alerts to stakeholders whenever the document moves forward through the process and to anyone who is listed as responsible when they have a task to complete.

## Status:
Inactive - unable to continue development, dependant software no longer in use

## Languages/Frameworks used:
* [Python](https://www.python.org/)
* [Flask](http://flask.pocoo.org/)
* [SQLAlchemy](https://www.sqlalchemy.org/)
* [WTForms](https://wtforms.readthedocs.io/)
* [Bootstrap](https://getbootstrap.com/)
* [Materialize](https://materializecss.com/)

## To do:
* Finish conversion from Bootstrap to Materialize
* In show_all_doc_changes(), change table so that it can sort id and submit_date by value, not alphabetical
* Receiving and error *FlaskWTFDeprecationWarning: "csrf_enabled" is deprecated and will be removed in 1.0. Set "meta.csrf" instead.* Workaround was to disable CSRF. Need to find a way to enable CSRF without breaking WTForms.
* Break the code into modules to separate views
* Add Flask-RESTful to create a REST API to help with generating emails
* Try porting to Django for comparison
