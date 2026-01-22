Database Activity Monitoring (DAM) System
Overview

The Database Activity Monitoring (DAM) System is a backend-driven security application built using Python (Flask) and MySQL.
It monitors database access, records user activities, and helps identify suspicious or unauthorized operations based on defined access rules.

The project demonstrates practical knowledge of database security, activity logging, and role-based access control.

Project Structure
dam_system/
│
├── app.py               # Main Flask application (backend logic)
├── schema.sql           # Database schema (tables & constraints)
├── seed.sql             # Sample data for testing
│
├── templates/           # Frontend HTML templates
│   ├── login.html
│   └── dashboard.html
│
└── README.md            # Project documentation

What This Project Does

The system tracks and records:

Who accessed the database

What operation was performed

When the activity occurred

It also helps detect suspicious or unauthorized behavior, such as:

Guests attempting to modify data

Failed login attempts

Users performing actions beyond their role permissions

Technologies Used

Python (Flask) – Backend application

MySQL – Database

HTML, CSS, JavaScript – Frontend interface

Object-Oriented Programming (OOP) – Structured backend design

Application Features
1. User Roles & Access Control

The system supports three user roles:

Admin

View and edit product data

View all database activity logs

User

View and edit product data

Guest

View-only access (read-only)

Access permissions are strictly enforced at the backend level.

2. Activity Logging

The system logs all critical actions, including:

Successful and failed login attempts

Product updates

Unauthorized access attempts

These logs are stored in the database and can be reviewed by administrators for auditing and security analysis.

3. Product Management

Products are displayed in a dashboard table

Admins and Users can edit product details directly

Changes are saved immediately to the database

Guests are restricted from making any modifications

4. Admin Monitoring Dashboard

Admins can monitor:

Which user performed an action

What data was modified

When the action occurred

This enables accountability, auditing, and behavior tracking.

How to Run the Project
1. Create the database schema
mysql -u root -p < schema.sql

2. Insert sample data
mysql -u root -p dam_system < seed.sql

3. Run the application
python app.py

4. Open in browser
http://localhost:5000

Demo Users
Role	Username
Admin	admin
User	john_doe
User	jane_smith
Guest	Guest login option