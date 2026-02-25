# 🎫 Ticket Raising System

A full-stack **Ticket Raising & Management System** that allows users to raise support tickets and admins/agents to manage, track, and resolve them efficiently.

This system ensures structured issue tracking, secure authentication, and role-based ticket handling.

---

## 🚀 Features

### 👤 User Features

- **User Registration & Login (JWT Authentication)**
- Raise a new support ticket
- View ticket status
- Reply to existing tickets
- View ticket history
- Secure logout

### 🛠️ Admin / Agent Features

- **Admin / Agent Login**
- View all tickets
- Filter tickets (Pending, In Progress, Resolved, Rejected)
- Assign tickets to agents
- Update ticket status
- Add internal notes
- Dashboard with statistics

---

## 🏗️ Tech Stack

### 🔹 Backend
- Python  
- Django  
- Django REST Framework  
- JWT Authentication  
- PostgreSQL  

### 🔹 Frontend
- React  
- Axios  
- React Router  
- Tailwind CSS  

### 🔹 Database
- PostgreSQL  

---

## 🔐 Authentication & Authorization

- JWT-based authentication  
- Access & Refresh tokens  
- Role-based access control (User / Admin / Agent)  
- Protected API routes  
- Secure password hashing  

---

## 📁 Project Structure

```
ticket-raising-system/
│
├── backend/
│   ├── apps/
│   ├── models.py
│   ├── views.py
│   ├── serializers.py
│   ├── urls.py
│   └── settings.py
│
├── frontend/
│   ├── components/
│   ├── pages/
│   ├── layouts/
│   └── api/
│
└── README.md
```

---

## ⚙️ Installation & Setup

### 🔹 Backend Setup

```bash
# Clone repository
git clone https://github.com/prithvirajpu/ticket-raising-system.git

# Navigate to backend folder
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\activate      # Windows
source venv/bin/activate   # Mac/Linux

# Install dependencies
pip install -r requirements.txt

# Run migrations
python manage.py migrate

# Start development server
python manage.py runserver
```

---

### 🔹 Frontend Setup

```bash
# Navigate to frontend folder
cd frontend

# Install dependencies
npm install

# Start React app
npm start
```

---

## 📊 Ticket Workflow

1. User creates a ticket  
2. Ticket status → **Pending**  
3. Admin assigns ticket to an agent  
4. Agent updates status → **In Progress**  
5. Ticket marked as **Resolved** or **Rejected**  
6. User can view updates anytime  

---

## 📌 Sample API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST   | `/api/auth/login/` | User login |
| POST   | `/api/tickets/` | Create ticket |
| GET    | `/api/tickets/` | List tickets |
| PATCH  | `/api/tickets/{id}/` | Update ticket |
| POST   | `/api/tickets/{id}/reply/` | Reply to ticket |

---

## 🛡️ Security Features

- JWT Authentication  
- Role-based permissions  
- Input validation  
- Password hashing  
- Protected routes  
- Secure API endpoints  

---

## 🎯 Future Enhancements

- Email notifications  
- Real-time updates (WebSockets)  
- File attachment support  
- SLA tracking  
- Analytics dashboard  
- Docker deployment  
- CI/CD integration  

---

## 👨‍💻 Author

**Prithviraj P U**
