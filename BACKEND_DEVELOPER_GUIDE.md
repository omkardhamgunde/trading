# Backend Developer Guide: Frontend-Backend Communication

## 🎯 For Backend Developers

This guide focuses on **what backend developers need to know** about frontend communication. We skip HTML/CSS/JavaScript basics and focus on the **connection points**.

---

## 🚀 **WHERE TO START?**

**If you're completely new to web development:**
1. Start with `LESSON_01_Web_Basics.md` (15 min)
2. Then `LESSON_02_Flask_Introduction.md` (30 min)
3. Then `LESSON_03_Routes_Views.md` (45 min)
4. Then `LESSON_04_Templates.md` (45 min)
5. **Finally**, read backend-frontend lessons below

**If you know web basics already:**
- Start directly with `LESSON_BACKEND_FRONTEND_01_API_JSON.md`

**Still confused?** Read `WHERE_TO_START.md` for a clear decision guide.

---

## 📚 Quick Reference

### Lesson 17: **JSON APIs** (`LESSON_BACKEND_FRONTEND_01_API_JSON.md`)
- Creating endpoints that return JSON
- Using `jsonify()` in Flask
- RESTful API design
- Status codes and error handling

### Lesson 18: **AJAX & Fetch** (`LESSON_BACKEND_FRONTEND_02_AJAX_FETCH.md`)
- How frontend makes HTTP requests
- Understanding `fetch()` from backend perspective
- CORS (Cross-Origin Resource Sharing)
- Debugging API calls

### Lesson 19: **WebSockets** (`LESSON_BACKEND_FRONTEND_03_WEBSOCKETS.md`)
- Real-time bidirectional communication
- Flask-SocketIO setup
- Pushing data from backend to frontend
- Background tasks for live updates

### Lesson 20: **Form Handling** (`LESSON_BACKEND_FRONTEND_04_FORMS.md`)
- How HTML forms submit to backend
- Using `request.form` and `request.args`
- WTForms for validation
- CSRF protection

---

## 🔄 Communication Patterns in Your Project

### Pattern 1: JSON API (AJAX)
**Example**: Stock search autocomplete

**Frontend:**
```javascript
fetch('/search_stocks?q=apple')
    .then(response => response.json())
    .then(data => showResults(data));
```

**Backend:**
```python
@watchlist_bp.route('/search_stocks')
def search_stocks_route():
    query = request.args.get('q')
    results = search_stocks(query)
    return jsonify(results)  # Returns JSON
```

---

### Pattern 2: Form Submission (Traditional)
**Example**: Trading form

**Frontend:**
```html
<form action="/trade" method="POST">
    <input name="stock_symbol" value="AAPL">
    <input name="quantity" value="10">
    <button type="submit">Trade</button>
</form>
```

**Backend:**
```python
@trading_bp.route('/trade', methods=['POST'])
def trade():
    stock_symbol = request.form['stock_symbol']
    quantity = int(request.form['quantity'])
    # Process trade...
    return redirect('/watchlist')  # Page reloads
```

---

### Pattern 3: WebSockets (Real-Time)
**Example**: Live price updates

**Frontend:**
```javascript
const socket = io();
socket.on('price_update', function(data) {
    updatePrices(data.prices);
});
```

**Backend:**
```python
@socketio.on('subscribe_watchlist')
def handle_subscribe(data):
    user_id = data['user_id']
    # Store connection...

# Background task pushes updates
socketio.emit('price_update', {'prices': prices}, room=sid)
```

---

## 🎓 Key Concepts for Backend Devs

### 1. **Backend Doesn't Care About Frontend**
- Whether it's React, Vue, or plain HTML
- Whether it's AJAX or form submission
- **You just handle HTTP requests!**

### 2. **Two Response Types:**
- **HTML**: `return render_template('page.html')`
- **JSON**: `return jsonify({'data': ...})`

### 3. **Three Request Types:**
- **GET**: `request.args` (query parameters)
- **POST (form)**: `request.form` (form data)
- **POST (JSON)**: `request.get_json()` (JSON body)

### 4. **Real-Time = WebSockets**
- HTTP = Request → Response (one-way)
- WebSocket = Persistent connection (bidirectional)

---

## 📖 Study Order

### If you know web basics:
1. **Start with**: `LESSON_BACKEND_FRONTEND_01_API_JSON.md` (Lesson 17)
   - Learn to create JSON endpoints
   - Understand RESTful design

2. **Then**: `LESSON_BACKEND_FRONTEND_02_AJAX_FETCH.md` (Lesson 18)
   - Understand how frontend calls your APIs
   - Learn to debug requests

3. **Next**: `LESSON_BACKEND_FRONTEND_03_WEBSOCKETS.md` (Lesson 19)
   - Real-time communication
   - Pushing data to frontend

4. **Finally**: `LESSON_BACKEND_FRONTEND_04_FORMS.md` (Lesson 20)
   - Traditional form handling
   - Validation and security

### If you're new to web development:
**First** complete Lessons 1-4 (Web fundamentals), **then** study Lessons 17-20 above.

---

## 🔗 In Your Project

### JSON APIs:
- `/search_stocks` → Stock search autocomplete

### Form Endpoints:
- `/login` → Login form
- `/trade` → Trading form
- `/watchlist` → Add stock form
- `/add_funds` → Add funds form

### WebSocket Events:
- `subscribe_watchlist` → Subscribe to price updates
- `subscribe_holdings` → Subscribe to holdings updates
- `price_update` → Backend pushes price changes
- `holdings_update` → Backend pushes holdings changes

---

## ❓ Common Questions

**Q: Do I need to know JavaScript?**
A: No! You just need to understand what frontend expects (JSON format, status codes, etc.)

**Q: How do I test my APIs?**
A: Use tools like Postman, curl, or browser's fetch() in console

**Q: What if frontend is on different domain?**
A: Enable CORS in Flask (see Lesson 2)

**Q: When to use WebSockets vs REST?**
A: WebSockets for real-time, REST for one-time requests

---

## 🚀 Ready to Learn?

**Not sure where to start?** Read `WHERE_TO_START.md` first!

**If you know web basics:** Start with **Lesson 17: APIs & JSON** (`LESSON_BACKEND_FRONTEND_01_API_JSON.md`)

**If you're new:** Start with **Lesson 1: Web Basics** (`LESSON_01_Web_Basics.md`)

**You'll understand how your backend connects with any frontend!** 🎯
