import os, sqlite3
from functools import wraps
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "vybe.db")
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(32)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(_error):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('musician','organizer','admin')),
      created_at TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS profiles (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      genre TEXT DEFAULT '', city TEXT DEFAULT '', bio TEXT DEFAULT '',
      instruments TEXT DEFAULT '', phone TEXT DEFAULT '', rate REAL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      organizer_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL, description TEXT DEFAULT '', venue TEXT NOT NULL,
      city TEXT NOT NULL, event_date TEXT NOT NULL, genre TEXT DEFAULT '',
      budget REAL DEFAULT 0, status TEXT NOT NULL DEFAULT 'published',
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS bookings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
      musician_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      note TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'pending',
      created_at TEXT NOT NULL, UNIQUE(event_id, musician_id)
    );
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      body TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      text TEXT NOT NULL, url TEXT DEFAULT '', is_read INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );
    """)
   
    # Create admin only when secure credentials are provided through environment variables.
    admin_email = os.environ.get("ADMIN_EMAIL")
    admin_password = os.environ.get("ADMIN_PASSWORD")

    if admin_email and admin_password:
        exists = conn.execute(
            "SELECT id FROM users WHERE email=?", (admin_email,)
        ).fetchone()

        if not exists:
            conn.execute(
                "INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                (
                    "VYBE Admin",
                    admin_email,
                    generate_password_hash(admin_password),
                    "admin",
                    datetime.now().isoformat(timespec="seconds")
                )
            )

    conn.commit()
    conn.close()

def current_user():
    if "user_id" not in session:
        return None
    return db().execute("SELECT * FROM users WHERE id=? AND active=1", (session["user_id"],)).fetchone()

@app.context_processor
def inject_globals():
    user = current_user()
    unread = 0
    if user:
        unread = db().execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0", (user["id"],)).fetchone()[0]
    return {"current_user": user, "unread_count": unread, "year": datetime.now().year}

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def roles(*allowed):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            if current_user()["role"] not in allowed:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator

def notify(user_id, message, target="notifications"):
    db().execute(
        "INSERT INTO notifications(user_id,text,url,created_at) VALUES(?,?,?,?)",
        (user_id, message, url_for(target), datetime.now().isoformat(timespec="seconds"))
    )

@app.route("/")
def index():
    conn = db()
    events = conn.execute("""SELECT e.*,u.name AS organizer FROM events e JOIN users u ON u.id=e.organizer_id
                             WHERE e.status='published' ORDER BY e.event_date LIMIT 6""").fetchall()
    musicians = conn.execute("""SELECT u.id,u.name,p.genre,p.city,p.bio FROM users u
                                JOIN profiles p ON p.user_id=u.id WHERE u.role='musician' AND u.active=1
                                ORDER BY u.created_at DESC LIMIT 6""").fetchall()
    return render_template("index.html", events=events, musicians=musicians)

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name","").strip()
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        role = request.form.get("role","musician")
        if not name or len(name) > 100 or "@" not in email or len(password) < 8 or role not in ("musician","organizer"):
            flash("Enter a valid name/email, choose a role, and use a password of at least 8 characters.", "error")
            return render_template("auth.html", mode="register")
        try:
            cur = db().execute(
                "INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                (name,email,generate_password_hash(password),role,datetime.now().isoformat(timespec="seconds"))
            )
            uid = cur.lastrowid
            if role == "musician":
                db().execute("INSERT INTO profiles(user_id) VALUES(?)",(uid,))
            db().commit()
            session["user_id"] = uid
            flash("Welcome to VYBE. Your account is ready.", "success")
            return redirect(url_for("dashboard"))
        except sqlite3.IntegrityError:
            db().rollback()
            flash("That email is already registered.", "error")
    return render_template("auth.html", mode="register")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        user = db().execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
        if user and user["active"] and check_password_hash(user["password_hash"],password):
            session.clear()
            session["user_id"] = user["id"]
            flash("You are signed in.", "success")
            return redirect(url_for("dashboard"))
        flash("Incorrect credentials or account disabled.", "error")
    return render_template("auth.html", mode="login")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    conn = db()
    if user["role"] == "admin":
        stats = {
            "users": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
            "events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "bookings": conn.execute("SELECT COUNT(*) FROM bookings").fetchone()[0],
            "pending": conn.execute("SELECT COUNT(*) FROM bookings WHERE status='pending'").fetchone()[0]
        }
        recent = conn.execute("""SELECT b.*,e.title,u.name AS musician FROM bookings b
          JOIN events e ON e.id=b.event_id JOIN users u ON u.id=b.musician_id
          ORDER BY b.id DESC LIMIT 6""").fetchall()
    elif user["role"] == "organizer":
        stats = {
            "events": conn.execute("SELECT COUNT(*) FROM events WHERE organizer_id=?",(user["id"],)).fetchone()[0],
            "requests": conn.execute("SELECT COUNT(*) FROM bookings b JOIN events e ON e.id=b.event_id WHERE e.organizer_id=?",(user["id"],)).fetchone()[0],
            "pending": conn.execute("SELECT COUNT(*) FROM bookings b JOIN events e ON e.id=b.event_id WHERE e.organizer_id=? AND b.status='pending'",(user["id"],)).fetchone()[0],
            "accepted": conn.execute("SELECT COUNT(*) FROM bookings b JOIN events e ON e.id=b.event_id WHERE e.organizer_id=? AND b.status='accepted'",(user["id"],)).fetchone()[0]
        }
        recent = conn.execute("""SELECT b.*,e.title,u.name AS musician FROM bookings b
          JOIN events e ON e.id=b.event_id JOIN users u ON u.id=b.musician_id
          WHERE e.organizer_id=? ORDER BY b.id DESC LIMIT 6""",(user["id"],)).fetchall()
    else:
        stats = {
            "applications": conn.execute("SELECT COUNT(*) FROM bookings WHERE musician_id=?",(user["id"],)).fetchone()[0],
            "pending": conn.execute("SELECT COUNT(*) FROM bookings WHERE musician_id=? AND status='pending'",(user["id"],)).fetchone()[0],
            "accepted": conn.execute("SELECT COUNT(*) FROM bookings WHERE musician_id=? AND status='accepted'",(user["id"],)).fetchone()[0],
            "events": conn.execute("SELECT COUNT(*) FROM events WHERE status='published'").fetchone()[0]
        }
        recent = conn.execute("""SELECT b.*,e.title,u.name AS organizer FROM bookings b
          JOIN events e ON e.id=b.event_id JOIN users u ON u.id=e.organizer_id
          WHERE b.musician_id=? ORDER BY b.id DESC LIMIT 6""",(user["id"],)).fetchall()
    return render_template("dashboard.html", stats=stats, recent=recent)

@app.route("/discover")
@login_required
def discover():
    q = request.args.get("q","").strip()
    genre = request.args.get("genre","").strip()
    city = request.args.get("city","").strip()
    sql = """SELECT u.id,u.name,p.genre,p.city,p.bio,p.instruments,p.rate FROM users u
             JOIN profiles p ON p.user_id=u.id WHERE u.role='musician' AND u.active=1"""
    params=[]
    if q:
        sql += " AND (u.name LIKE ? OR p.bio LIKE ? OR p.instruments LIKE ?)"
        params += [f"%{q}%"]*3
    if genre:
        sql += " AND p.genre LIKE ?"; params.append(f"%{genre}%")
    if city:
        sql += " AND p.city LIKE ?"; params.append(f"%{city}%")
    sql += " ORDER BY u.name"
    musicians = db().execute(sql,params).fetchall()
    return render_template("discover.html", musicians=musicians, q=q, genre=genre, city=city)

@app.route("/profile", methods=["GET","POST"])
@roles("musician")
def profile():
    user=current_user()
    if request.method=="POST":
        values=[request.form.get(k,"").strip() for k in ("genre","city","bio","instruments","phone")]
        try: rate=max(0,float(request.form.get("rate") or 0))
        except ValueError: rate=0
        db().execute("""INSERT INTO profiles(user_id,genre,city,bio,instruments,phone,rate)
          VALUES(?,?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET genre=excluded.genre,city=excluded.city,
          bio=excluded.bio,instruments=excluded.instruments,phone=excluded.phone,rate=excluded.rate""",
          (user["id"],*values,rate))
        db().commit()
        flash("Your musician profile has been saved.","success")
        return redirect(url_for("profile"))
    data=db().execute("SELECT * FROM profiles WHERE user_id=?",(user["id"],)).fetchone()
    return render_template("profile.html", profile=data)

@app.route("/events")
@login_required
def events():
    q=request.args.get("q","").strip()
    city=request.args.get("city","").strip()
    sql="""SELECT e.*,u.name AS organizer FROM events e JOIN users u ON u.id=e.organizer_id
           WHERE e.status='published'"""
    params=[]
    if q:
        sql+=" AND (e.title LIKE ? OR e.genre LIKE ? OR e.description LIKE ?)"
        params += [f"%{q}%"]*3
    if city:
        sql+=" AND e.city LIKE ?"; params.append(f"%{city}%")
    sql+=" ORDER BY e.event_date"
    rows=db().execute(sql,params).fetchall()
    return render_template("events.html", events=rows, q=q, city=city)

@app.route("/events/new", methods=["GET","POST"])
@roles("organizer")
def event_new():
    if request.method=="POST":
        title=request.form.get("title","").strip()
        venue=request.form.get("venue","").strip()
        city=request.form.get("city","").strip()
        date=request.form.get("event_date","").strip()
        if not title or not venue or not city or not date:
            flash("Title, venue, city and date are required.","error")
        else:
            try:
                datetime.strptime(date,"%Y-%m-%d")
                budget=max(0,float(request.form.get("budget") or 0))
                cur=db().execute("""INSERT INTO events(organizer_id,title,description,venue,city,event_date,genre,budget,status,created_at)
                  VALUES(?,?,?,?,?,?,?,?,?,?)""",(current_user()["id"],title,request.form.get("description","").strip(),
                  venue,city,date,request.form.get("genre","").strip(),budget,"published",datetime.now().isoformat(timespec="seconds")))
                db().commit()
                flash("Event published successfully.","success")
                return redirect(url_for("event_detail",event_id=cur.lastrowid))
            except (ValueError,sqlite3.Error):
                db().rollback(); flash("Please enter a valid date and budget.","error")
    return render_template("event_form.html", event=None)

@app.route("/events/<int:event_id>")
@login_required
def event_detail(event_id):
    event=db().execute("""SELECT e.*,u.name AS organizer FROM events e JOIN users u ON u.id=e.organizer_id WHERE e.id=?""",(event_id,)).fetchone()
    if not event: abort(404)
    own = current_user()["id"]==event["organizer_id"]
    booking=None
    if current_user()["role"]=="musician":
        booking=db().execute("SELECT * FROM bookings WHERE event_id=? AND musician_id=?",(event_id,current_user()["id"])).fetchone()
    return render_template("event_detail.html",event=event,own=own,booking=booking)

@app.route("/events/<int:event_id>/edit", methods=["GET","POST"])
@roles("organizer")
def event_edit(event_id):
    event=db().execute("SELECT * FROM events WHERE id=? AND organizer_id=?",(event_id,current_user()["id"])).fetchone()
    if not event: abort(404)
    if request.method=="POST":
        title=request.form.get("title","").strip(); venue=request.form.get("venue","").strip()
        city=request.form.get("city","").strip(); date=request.form.get("event_date","").strip()
        try:
            datetime.strptime(date,"%Y-%m-%d")
            db().execute("""UPDATE events SET title=?,description=?,venue=?,city=?,event_date=?,genre=?,budget=?
              WHERE id=? AND organizer_id=?""",(title,request.form.get("description","").strip(),venue,city,date,
              request.form.get("genre","").strip(),max(0,float(request.form.get("budget") or 0)),event_id,current_user()["id"]))
            db().commit(); flash("Event updated.","success"); return redirect(url_for("event_detail",event_id=event_id))
        except (ValueError,sqlite3.Error):
            db().rollback(); flash("Check the event details and try again.","error")
    return render_template("event_form.html",event=event)

@app.post("/events/<int:event_id>/delete")
@roles("organizer")
def event_delete(event_id):
    cur=db().execute("DELETE FROM events WHERE id=? AND organizer_id=?",(event_id,current_user()["id"]))
    db().commit()
    if cur.rowcount: flash("Event deleted.","success")
    else: flash("Event not found or not yours.","error")
    return redirect(url_for("events"))

@app.post("/events/<int:event_id>/book")
@roles("musician")
def book_event(event_id):
    event=db().execute("SELECT * FROM events WHERE id=? AND status='published'",(event_id,)).fetchone()
    if not event: abort(404)
    try:
        db().execute("INSERT INTO bookings(event_id,musician_id,note,status,created_at) VALUES(?,?,?,?,?)",
          (event_id,current_user()["id"],request.form.get("note","").strip(),"pending",datetime.now().isoformat(timespec="seconds")))
        notify(event["organizer_id"],f"{current_user()['name']} requested to book your event.")
        db().commit(); flash("Booking request sent to the organizer.","success")
    except sqlite3.IntegrityError:
        db().rollback(); flash("You have already requested this event.","warning")
    return redirect(url_for("event_detail",event_id=event_id))

@app.route("/bookings")
@login_required
def bookings():
    user=current_user()
    if user["role"]=="organizer":
        rows=db().execute("""SELECT b.*,e.title,e.event_date,u.name AS musician FROM bookings b
          JOIN events e ON e.id=b.event_id JOIN users u ON u.id=b.musician_id
          WHERE e.organizer_id=? ORDER BY b.id DESC""",(user["id"],)).fetchall()
    elif user["role"]=="musician":
        rows=db().execute("""SELECT b.*,e.title,e.event_date,u.name AS organizer FROM bookings b
          JOIN events e ON e.id=b.event_id JOIN users u ON u.id=e.organizer_id
          WHERE b.musician_id=? ORDER BY b.id DESC""",(user["id"],)).fetchall()
    else:
        rows=db().execute("""SELECT b.*,e.title,e.event_date,u.name AS musician FROM bookings b
          JOIN events e ON e.id=b.event_id JOIN users u ON u.id=b.musician_id ORDER BY b.id DESC""").fetchall()
    return render_template("bookings.html",bookings=rows)

@app.post("/bookings/<int:booking_id>/status")
@roles("organizer","admin")
def booking_status(booking_id):
    status=request.form.get("status")
    if status not in ("accepted","rejected","completed"): abort(400)
    row=db().execute("""SELECT b.*,e.organizer_id,e.title FROM bookings b JOIN events e ON e.id=b.event_id WHERE b.id=?""",(booking_id,)).fetchone()
    if not row: abort(404)
    if current_user()["role"]=="organizer" and row["organizer_id"]!=current_user()["id"]: abort(403)
    db().execute("UPDATE bookings SET status=? WHERE id=?",(status,booking_id))
    notify(row["musician_id"],f"Your booking for '{row['title']}' was {status}.")
    db().commit(); flash(f"Booking marked {status}.","success")
    return redirect(request.referrer or url_for("bookings"))

@app.route("/messages", methods=["GET","POST"])
@login_required
def messages():
    user=current_user()
    if request.method=="POST":
        try: receiver_id=int(request.form.get("receiver_id",""))
        except ValueError: abort(400)
        body=request.form.get("body","").strip()
        receiver=db().execute("SELECT id FROM users WHERE id=? AND active=1",(receiver_id,)).fetchone()
        if not receiver or receiver_id==user["id"] or not body or len(body)>2000:
            flash("Choose a valid recipient and enter a message (max 2,000 characters).","error")
        else:
            db().execute("INSERT INTO messages(sender_id,receiver_id,body,created_at) VALUES(?,?,?,?)",
              (user["id"],receiver_id,body,datetime.now().isoformat(timespec="seconds")))
            notify(receiver_id,f"New message from {user['name']}.")
            db().commit(); flash("Message sent.","success")
        return redirect(url_for("messages",with_user=receiver_id))
    contacts=db().execute("""SELECT DISTINCT u.id,u.name,u.role FROM users u JOIN messages m
      ON (u.id=m.sender_id OR u.id=m.receiver_id) WHERE (m.sender_id=? OR m.receiver_id=?) AND u.id<>?
      ORDER BY u.name""",(user["id"],user["id"],user["id"])).fetchall()
    people=db().execute("SELECT id,name,role FROM users WHERE active=1 AND id<>? ORDER BY name",(user["id"],)).fetchall()
    try: other_id=int(request.args.get("with_user","0"))
    except ValueError: other_id=0
    other=next((p for p in people if p["id"]==other_id),None)
    thread=[]
    if other:
        thread=db().execute("""SELECT m.*,s.name AS sender_name FROM messages m JOIN users s ON s.id=m.sender_id
          WHERE (m.sender_id=? AND m.receiver_id=?) OR (m.sender_id=? AND m.receiver_id=?)
          ORDER BY m.id""",(user["id"],other_id,other_id,user["id"])).fetchall()
    return render_template("messages.html",contacts=contacts,people=people,other=other,thread=thread)

@app.route("/notifications")
@login_required
def notifications():
    rows=db().execute("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 100",(current_user()["id"],)).fetchall()
    db().execute("UPDATE notifications SET is_read=1 WHERE user_id=?",(current_user()["id"],)); db().commit()
    return render_template("notifications.html",notifications=rows)

@app.route("/admin")
@roles("admin")
def admin():
    users=db().execute("SELECT id,name,email,role,active,created_at FROM users ORDER BY id DESC").fetchall()
    return render_template("admin.html",users=users)

@app.post("/admin/users/<int:user_id>/toggle")
@roles("admin")
def toggle_user(user_id):
    if user_id==current_user()["id"]:
        flash("You cannot disable your own admin account.","error")
    else:
        db().execute("UPDATE users SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id=?",(user_id,))
        db().commit(); flash("User access updated.","success")
    return redirect(url_for("admin"))

@app.route("/reports")
@roles("admin","organizer")
def reports():
    if current_user()["role"]=="organizer":
        args=(current_user()["id"],)
        totals=db().execute("""SELECT COUNT(*) total,
          SUM(CASE WHEN b.status='pending' THEN 1 ELSE 0 END) pending,
          SUM(CASE WHEN b.status='accepted' THEN 1 ELSE 0 END) accepted,
          SUM(CASE WHEN b.status='rejected' THEN 1 ELSE 0 END) rejected
          FROM bookings b JOIN events e ON e.id=b.event_id WHERE e.organizer_id=?""",args).fetchone()
        event_rows=db().execute("SELECT title,event_date FROM events WHERE organizer_id=? ORDER BY event_date DESC",args).fetchall()
    else:
        totals=db().execute("""SELECT COUNT(*) total,
          SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) pending,
          SUM(CASE WHEN status='accepted' THEN 1 ELSE 0 END) accepted,
          SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) rejected FROM bookings""").fetchone()
        event_rows=db().execute("SELECT title,event_date FROM events ORDER BY event_date DESC LIMIT 30").fetchall()
    return render_template("reports.html",totals=totals,event_rows=event_rows)

@app.errorhandler(403)
def forbidden(_): return render_template("error.html",code=403,message="You don't have permission to access this page."),403
@app.errorhandler(404)
def not_found(_): return render_template("error.html",code=404,message="We couldn't find that page."),404

with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=False)
