# VYBE — Local Musician Platform (Fresh Build)

A fresh Flask + SQLite implementation based on the CSE 326 project brief:
- Role-based user registration/login (Musician, Organizer, Admin)
- Role-aware dashboards
- CRUD for musician profiles and organizer events
- Search/filter for musicians and events
- Booking request workflow with pending/accepted/rejected/completed states
- Member messaging and in-app notifications
- Admin user access management
- Basic booking/event reporting
- Form validation, duplicate booking protection, and role/ownership checks

## Requirements
- Python 3.10 or newer
- Flask (only third-party runtime dependency)
- SQLite is included with Python

## Windows setup (PowerShell)
Open the folder containing `app.py` in VS Code terminal, then run:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Open http://127.0.0.1:5000

## Demo admin
- Email: `admin@vybe.local`
- Password: `Admin@123`

Change the demo password / secret before deploying publicly. The admin account is created automatically the first time the database initializes.

## Database
The app creates `vybe.db` automatically in this project folder. Keep this file to retain your local users, events, bookings, messages and notifications. Back it up before replacing the project.

## Notes
- This is a college-project starter implementation, not a production-hardened service.
- For public deployment, set a strong `SECRET_KEY`, use HTTPS, add CSRF protection, rate limiting, email verification and a production WSGI server.
- `debug=True` is for local development only.
