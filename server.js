// Employee REST API with Bearer Token Authentication
// Node.js + Express + JWT

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-2024';
const JWT_EXPIRES_IN = '24h';

// Middleware
app.use(cors());
app.use(express.json());

// Mock Users Database (for authentication)
const users = [
  {
    id: 1,
    username: 'admin',
    email: 'admin@company.com',
    password: 'admin123', // In real app, use bcrypt hash
    role: 'admin'
  },
  {
    id: 2,
    username: 'hr_manager',
    email: 'hr@company.com',
    password: 'hr123',
    role: 'hr'
  }
];

// Mock Employees Database
let employees = [
  {
    id: 1,
    firstName: 'John',
    lastName: 'Doe',
    email: 'john.doe@company.com',
    phone: '+1-555-0101',
    department: 'Engineering',
    position: 'Senior Developer',
    salary: 85000,
    hireDate: '2022-01-15',
    status: 'active',
    createdAt: '2022-01-15T09:00:00Z',
    updatedAt: '2022-01-15T09:00:00Z'
  },
  {
    id: 2,
    firstName: 'Jane',
    lastName: 'Smith',
    email: 'jane.smith@company.com',
    phone: '+1-555-0102',
    department: 'Marketing',
    position: 'Marketing Manager',
    salary: 75000,
    hireDate: '2021-08-20',
    status: 'active',
    createdAt: '2021-08-20T10:30:00Z',
    updatedAt: '2021-08-20T10:30:00Z'
  },
  {
    id: 3,
    firstName: 'Mike',
    lastName: 'Johnson',
    email: 'mike.johnson@company.com',
    phone: '+1-555-0103',
    department: 'Sales',
    position: 'Sales Representative',
    salary: 55000,
    hireDate: '2023-03-10',
    status: 'active',
    createdAt: '2023-03-10T14:15:00Z',
    updatedAt: '2023-03-10T14:15:00Z'
  }
];

let nextEmployeeId = 4;

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
  
  console.log('Auth Header:', authHeader);
  console.log('Token:', token);
  
  if (!token) {
    return res.status(401).json({ 
      error: 'Access token required',
      message: 'Please provide Bearer token in Authorization header'
    });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log('Token verification error:', err.message);
      return res.status(403).json({ 
        error: 'Invalid or expired token',
        message: 'Please login again to get a new token'
      });
    }
    
    req.user = user;
    console.log('Authenticated user:', user);
    next();
  });
};

// Admin role check middleware
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin' && req.user.role !== 'hr') {
    return res.status(403).json({
      error: 'Access denied',
      message: 'Admin or HR role required',
      yourRole: req.user.role
    });
  }
  next();
};

// ============ AUTHENTICATION ENDPOINTS ============

// POST /api/auth/login - Login and get Bearer token
app.post('/api/auth/login', async (req, res) => {
  console.log('Login attempt:', req.body);
  
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ 
      error: 'Username and password required' 
    });
  }
  
  try {
    // Find user
    const user = users.find(u => u.username === username);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check password (in real app, use bcrypt.compare)
    if (user.password !== password) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate JWT token
    const tokenPayload = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role
    };
    
    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    
    console.log('Login successful for:', user.username);
    
    res.json({
      success: true,
      message: 'Login successful',
      token: token,
      tokenType: 'Bearer',
      expiresIn: JWT_EXPIRES_IN,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/auth/verify - Verify token
app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({
    valid: true,
    user: req.user,
    message: 'Token is valid'
  });
});

// ============ EMPLOYEE ENDPOINTS ============

// GET /api/employees - Get all employees
app.get('/api/employees', authenticateToken, (req, res) => {
  const { page = 1, limit = 10, department, status = 'active' } = req.query;
  
  let filteredEmployees = employees.filter(emp => emp.status === status);
  
  if (department) {
    filteredEmployees = filteredEmployees.filter(emp => 
      emp.department.toLowerCase().includes(department.toLowerCase())
    );
  }
  
  const startIndex = (page - 1) * limit;
  const endIndex = startIndex + parseInt(limit);
  const paginatedEmployees = filteredEmployees.slice(startIndex, endIndex);
  
  res.json({
    success: true,
    message: 'Employees fetched successfully',
    data: paginatedEmployees,
    pagination: {
      currentPage: parseInt(page),
      totalPages: Math.ceil(filteredEmployees.length / limit),
      totalEmployees: filteredEmployees.length,
      limit: parseInt(limit)
    },
    requestedBy: req.user.username
  });
});

// GET /api/employees/:id - Get employee by ID
app.get('/api/employees/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const employee = employees.find(emp => emp.id === parseInt(id));
  
  if (!employee) {
    return res.status(404).json({
      error: 'Employee not found',
      message: `No employee found with ID: ${id}`
    });
  }
  
  res.json({
    success: true,
    message: 'Employee fetched successfully',
    data: employee,
    requestedBy: req.user.username
  });
});

// POST /api/employees - Create new employee
app.post('/api/employees', authenticateToken, requireAdmin, (req, res) => {
  console.log('Create employee request:', req.body);
  
  const {
    firstName,
    lastName,
    email,
    phone,
    department,
    position,
    salary,
    hireDate
  } = req.body;
  
  // Validation
  if (!firstName || !lastName || !email || !department || !position) {
    return res.status(400).json({
      error: 'Missing required fields',
      required: ['firstName', 'lastName', 'email', 'department', 'position']
    });
  }
  
  // Check if email already exists
  const existingEmployee = employees.find(emp => emp.email === email);
  if (existingEmployee) {
    return res.status(409).json({
      error: 'Email already exists',
      message: `Employee with email ${email} already exists`
    });
  }
  
  // Create new employee
  const newEmployee = {
    id: nextEmployeeId++,
    firstName,
    lastName,
    email,
    phone: phone || '',
    department,
    position,
    salary: salary || 0,
    hireDate: hireDate || new Date().toISOString().split('T')[0],
    status: 'active',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  
  employees.push(newEmployee);
  
  console.log('Employee created:', newEmployee);
  
  res.status(201).json({
    success: true,
    message: 'Employee created successfully',
    data: newEmployee,
    createdBy: req.user.username
  });
});

// PUT /api/employees/:id - Update employee
app.put('/api/employees/:id', authenticateToken, requireAdmin, (req, res) => {
  const { id } = req.params;
  const employeeIndex = employees.findIndex(emp => emp.id === parseInt(id));
  
  if (employeeIndex === -1) {
    return res.status(404).json({
      error: 'Employee not found',
      message: `No employee found with ID: ${id}`
    });
  }
  
  const {
    firstName,
    lastName,
    email,
    phone,
    department,
    position,
    salary,
    status
  } = req.body;
  
  // Check if email is being changed and already exists
  if (email && email !== employees[employeeIndex].email) {
    const existingEmployee = employees.find(emp => emp.email === email);
    if (existingEmployee) {
      return res.status(409).json({
        error: 'Email already exists',
        message: `Another employee with email ${email} already exists`
      });
    }
  }
  
  // Update employee
  const updatedEmployee = {
    ...employees[employeeIndex],
    firstName: firstName || employees[employeeIndex].firstName,
    lastName: lastName || employees[employeeIndex].lastName,
    email: email || employees[employeeIndex].email,
    phone: phone !== undefined ? phone : employees[employeeIndex].phone,
    department: department || employees[employeeIndex].department,
    position: position || employees[employeeIndex].position,
    salary: salary !== undefined ? salary : employees[employeeIndex].salary,
    status: status || employees[employeeIndex].status,
    updatedAt: new Date().toISOString()
  };
  
  employees[employeeIndex] = updatedEmployee;
  
  console.log('Employee updated:', updatedEmployee);
  
  res.json({
    success: true,
    message: 'Employee updated successfully',
    data: updatedEmployee,
    updatedBy: req.user.username
  });
});

// PATCH /api/employees/:id - Partial update employee
app.patch('/api/employees/:id', authenticateToken, requireAdmin, (req, res) => {
  const { id } = req.params;
  const employeeIndex = employees.findIndex(emp => emp.id === parseInt(id));
  
  if (employeeIndex === -1) {
    return res.status(404).json({
      error: 'Employee not found',
      message: `No employee found with ID: ${id}`
    });
  }
  
  // Update only provided fields
  const allowedFields = ['firstName', 'lastName', 'email', 'phone', 'department', 'position', 'salary', 'status'];
  const updates = {};
  
  allowedFields.forEach(field => {
    if (req.body[field] !== undefined) {
      updates[field] = req.body[field];
    }
  });
  
  if (Object.keys(updates).length === 0) {
    return res.status(400).json({
      error: 'No valid fields to update',
      allowedFields: allowedFields
    });
  }
  
  // Check email uniqueness if being updated
  if (updates.email && updates.email !== employees[employeeIndex].email) {
    const existingEmployee = employees.find(emp => emp.email === updates.email);
    if (existingEmployee) {
      return res.status(409).json({
        error: 'Email already exists'
      });
    }
  }
  
  employees[employeeIndex] = {
    ...employees[employeeIndex],
    ...updates,
    updatedAt: new Date().toISOString()
  };
  
  res.json({
    success: true,
    message: 'Employee updated successfully',
    data: employees[employeeIndex],
    updatedFields: Object.keys(updates),
    updatedBy: req.user.username
  });
});

// DELETE /api/employees/:id - Delete employee (soft delete)
app.delete('/api/employees/:id', authenticateToken, requireAdmin, (req, res) => {
  const { id } = req.params;
  const { permanent = false } = req.query;
  
  const employeeIndex = employees.findIndex(emp => emp.id === parseInt(id));
  
  if (employeeIndex === -1) {
    return res.status(404).json({
      error: 'Employee not found',
      message: `No employee found with ID: ${id}`
    });
  }
  
  if (permanent === 'true') {
    // Permanent delete
    const deletedEmployee = employees.splice(employeeIndex, 1)[0];
    
    res.json({
      success: true,
      message: 'Employee deleted Successfully',
      data: deletedEmployee,
      deletedBy: req.user.username,
      permanent: true
    });
  } else {
    // Soft delete (change status to inactive)
    employees[employeeIndex].status = 'inactive';
    employees[employeeIndex].updatedAt = new Date().toISOString();
    
    res.json({
      success: true,
      message: 'Employee deactivated (soft delete)',
      data: employees[employeeIndex],
      deletedBy: req.user.username,
      permanent: false
    });
  }
});

// GET /api/employees/stats/summary - Employee statistics
app.get('/api/employees/stats/summary', authenticateToken, (req, res) => {
  const totalEmployees = employees.length;
  const activeEmployees = employees.filter(emp => emp.status === 'active').length;
  const inactiveEmployees = employees.filter(emp => emp.status === 'inactive').length;
  
  const departmentStats = employees.reduce((acc, emp) => {
    acc[emp.department] = (acc[emp.department] || 0) + 1;
    return acc;
  }, {});
  
  res.json({
    success: true,
    data: {
      totalEmployees,
      activeEmployees,
      inactiveEmployees,
      departmentBreakdown: departmentStats,
      averageSalary: Math.round(employees.reduce((sum, emp) => sum + emp.salary, 0) / employees.length)
    },
    requestedBy: req.user.username
  });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    message: 'Employee API is running',
    timestamp: new Date().toISOString(),
    endpoints: {
      auth: '/api/auth/login',
      employees: '/api/employees',
      stats: '/api/employees/stats/summary'
    }
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: err.message
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`\n🚀 Employee REST API Server running on http://localhost:${PORT}`);
  console.log('\n📋 POSTMAN TEST CREDENTIALS:');
  console.log('Username: admin, Password: admin123 (Admin access)');
  console.log('Username: hr_manager, Password: hr123 (HR access)');
  console.log('\n🔗 API ENDPOINTS:\n');
  
  const endpoints = [
    'POST   /api/auth/login           - Login and get Bearer token',
    'GET    /api/auth/verify          - Verify token',
    'GET    /api/employees            - Get all employees',
    'GET    /api/employees/:id        - Get employee by ID',
    'POST   /api/employees            - Create new employee',
    'PUT    /api/employees/:id        - Update employee (full)',
    'PATCH  /api/employees/:id        - Update employee (partial)',
    'DELETE /api/employees/:id        - Delete employee (soft delete)',
    'DELETE /api/employees/:id?permanent=true - Permanent delete',
    'GET    /api/employees/stats/summary - Employee statistics',
    'GET    /api/health               - Health check'
  ];
  
  endpoints.forEach(endpoint => console.log(`  ${endpoint}`));
  console.log('\n📝 Remember to add Bearer token in Authorization header!\n');
});

/*
============== POSTMAN SETUP INSTRUCTIONS ==============

1. INSTALLATION:
   npm init -y
   npm install express jsonwebtoken bcrypt cors

2. RUN SERVER:
   node server.js

3. POSTMAN CONFIGURATION:
   Step 1: Login to get Bearer token
   POST http://localhost:3000/api/auth/login
   Body (JSON): 
   {
     "username": "admin",
     "password": "admin123"
   }
   
   Step 2: Copy the "token" from response
   
   Step 3: For all other requests, add Authorization header:
   Authorization: Bearer YOUR_TOKEN_HERE

4. TEST EMPLOYEE ENDPOINTS:

   GET /api/employees
   Headers: Authorization: Bearer YOUR_TOKEN
   
   POST /api/employees
   Headers: Authorization: Bearer YOUR_TOKEN
   Body (JSON):
   {
     "firstName": "Alice",
     "lastName": "Brown",
     "email": "alice.brown@company.com",
     "phone": "+1-555-0104",
     "department": "IT",
     "position": "Software Engineer",
     "salary": 70000,
     "hireDate": "2024-01-15"
   }
   
   PUT /api/employees/1
   Headers: Authorization: Bearer YOUR_TOKEN
   Body (JSON):
   {
     "firstName": "John",
     "lastName": "Doe Updated",
     "salary": 90000,
     "position": "Lead Developer"
   }
   
   DELETE /api/employees/1
   Headers: Authorization: Bearer YOUR_TOKEN

5. EXPECTED BEHAVIOR:
   - Login returns JWT Bearer token
   - All employee endpoints require valid Bearer token
   - Admin/HR role required for create/update/delete
   - Soft delete by default, permanent delete with ?permanent=true

============== READY FOR POSTMAN TESTING ==============
*/