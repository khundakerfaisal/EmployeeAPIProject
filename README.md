## Employee API With Newman Report 
## Prerequisite
- Postman
- NodeJS
- Visual Studio Code
## About This Project
This is Employee API collection automation project.Here we have Create,update,get data and delete Employee information with assertion.
Here we have validate the test case and generate newman report. (If need more specific details write here about the project section)

## How to run this project
- ```Clone This Project``` [Employee API Project](https://github.com/khundakerfaisal/EmployeeAPIProject)
- ```Hit The Command```
 
## API Documentation [API Document File](https://documenter.getpostman.com/view/25113210/2sB3HnKf8e) 
## Newman Report [Just DRAG AND DROP]
## API Request
    'POST   /api/auth/login           - Login and get Bearer token',
    'GET    /api/auth/verify          - Verify token',
    'GET    /api/employees            - Get all employees',
    'GET    /api/employees/:id        - Get employee by ID',
    'POST   /api/employees            - Create new employee',
    'PUT    /api/employees/:id        - Update employee (full)',
    'PATCH  /api/employees/:id        - Update employee (partial)',
    'DELETE /api/employees/:id        - Delete employee (soft delete)',
    'DELETE /api/employees/:id?permanent=true - Permanent delete',
## Query PARAM
```bash
'GET   /api/employees?id=1'
```
```bash
'GET   /api/employees?id=1,2,3,4,5'
```
```bash
'GET   /api/employees?department=Engineering	'
```
```bash
'GET   /api/employees?phone=0215151	'
```
```bash
'GET   /api/employees?email=a@yahoo.com	'
```
```bash
'GET   /api/employees?id=1&phone=0215151	'
```
```bash
'GET  /api/employees?id=1&phone=0215151&email=a@yahoo.com	'
```
```bash
'GET  /api/employees?department=Engineering'
```
