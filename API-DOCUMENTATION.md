# Employee CRUD API Documentation

## Base URL

```text
http://localhost:3000
```

For a deployed service, replace the base URL with the deployed API URL.

## Authentication

All employee endpoints require a Bearer token.

### Login

```http
POST /api/auth/login
Content-Type: application/json
```

Request body:

```json
{
  "username": "admin",
  "password": "admin123"
}
```

Use the `token` returned by login in every employee request:

```http
Authorization: Bearer YOUR_TOKEN
```

## Employee Fields

| Field | Type | Example |
| --- | --- | --- |
| `id` | number | `1` |
| `firstName` | string | `John` |
| `lastName` | string | `Doe` |
| `email` | string | `john.doe@company.com` |
| `phone` | string | `01712345678` |
| `department` | string | `Engineering` |
| `position` | string | `Senior Developer` |
| `salary` | number | `85000` |
| `hireDate` | date string | `2022-01-15` |
| `status` | string | `active` |
| `createdAt` | ISO date string | `2022-01-15T09:00:00Z` |
| `updatedAt` | ISO date string | `2022-01-15T09:00:00Z` |

## GET Employees

### Get all employees

```http
GET /api/employees
Authorization: Bearer YOUR_TOKEN
```

The response contains `data` and pagination information:

```json
{
  "success": true,
  "message": "Employees fetched successfully",
  "data": [],
  "pagination": {
    "currentPage": 1,
    "totalPages": 1,
    "totalEmployees": 3,
    "limit": 10
  }
}
```

### Pagination parameters

```http
GET /api/employees?page=1&limit=10
```

- `page` selects the page number. Default: `1`.
- `limit` selects the number of records per page. Default: `10`.

### Search behavior

- Different fields are combined with **AND**. Every supplied field must match.
- Multiple values in one field are combined with **OR**.
- Comma-separated values are supported, for example `id=1,2,3`.
- Text matching is case-insensitive and supports partial text matches.
- `id` and `salary` use numeric equality matching.
- An unknown field returns no matching records.

### Search examples

| Request | Result |
| --- | --- |
| `/api/employees?id=1` | Returns employee ID `1`. |
| `/api/employees?id=1,2,3,4,5` | Returns employees whose IDs are `1`, `2`, `3`, `4`, or `5`. Existing IDs only are returned. |
| `/api/employees?department=Engineering` | Returns employees whose department contains `Engineering`. |
| `/api/employees?phone=0215151` | Returns employees whose phone contains `0215151`. |
| `/api/employees?email=a@yahoo.com` | Returns employees whose email contains `a@yahoo.com`. |
| `/api/employees?id=1&phone=0215151` | Returns employee ID `1` only if its phone also contains `0215151`; otherwise returns an empty `data` array. |
| `/api/employees?id=1&phone=0215151&email=a@yahoo.com` | Returns a record only when ID, phone, and email all match the same employee. |
| `/api/employees?department=Engineering&status=active` | Returns active employees in the Engineering department. |
| `/api/employees?id=1,2&department=Engineering` | Returns employees with ID `1` or `2` whose department contains `Engineering`. |

Equivalent repeated query parameters are also accepted by Express:

```http
GET /api/employees?id=1&id=2&id=3
```

## GET Employee by ID

```http
GET /api/employees/1
Authorization: Bearer YOUR_TOKEN
```

Success response:

```json
{
  "success": true,
  "message": "Employee fetched successfully",
  "data": {
    "id": 1,
    "firstName": "John",
    "lastName": "Doe",
    "email": "john.doe@company.com",
    "phone": "01712345678",
    "department": "Engineering",
    "position": "Senior Developer",
    "salary": 85000,
    "hireDate": "2022-01-15",
    "status": "active",
    "createdAt": "2022-01-15T09:00:00Z",
    "updatedAt": "2022-01-15T09:00:00Z"
  }
}
```

## Create Employee

```http
POST /api/employees
Authorization: Bearer YOUR_TOKEN
Content-Type: application/json
```

Admin or HR access is required.

Request body:

```json
{
  "firstName": "Alice",
  "lastName": "Brown",
  "email": "alice.brown@company.com",
  "phone": "01712345678",
  "department": "IT",
  "position": "Software Engineer",
  "salary": 70000,
  "hireDate": "2024-01-15"
}
```

Required fields: `firstName`, `lastName`, `email`, `phone`, `department`, and `position`.

The phone must contain exactly 11 digits and use Bangladesh mobile format, such as `01712345678`. Values such as `+8801712345678`, `8801712345678`, spaces, and hyphens are rejected. Phone numbers must be unique.

The server automatically creates `id`, `status`, `createdAt`, and `updatedAt`.

## Update Employee with PUT

`PUT` updates the supplied employee and preserves omitted values.

```http
PUT /api/employees/1
Authorization: Bearer YOUR_TOKEN
Content-Type: application/json
```

Admin or HR access is required.

Request body:

```json
{
  "firstName": "John",
  "lastName": "Doe Updated",
  "email": "john.updated@company.com",
  "phone": "01712345679",
  "department": "Engineering",
  "position": "Lead Developer",
  "salary": 90000,
  "status": "active"
}
```

## Partial Update Employee with PATCH

`PATCH` updates only the allowed fields included in the request.

```http
PATCH /api/employees/1
Authorization: Bearer YOUR_TOKEN
Content-Type: application/json
```

Admin or HR access is required.

Request body:

```json
{
  "salary": 95000,
  "position": "Principal Developer"
}
```

Allowed PATCH fields: `firstName`, `lastName`, `email`, `phone`, `department`, `position`, `salary`, and `status`.

## Delete Employee

### Soft delete

Soft delete changes the employee status to `inactive`.

```http
DELETE /api/employees/1
Authorization: Bearer YOUR_TOKEN
```

Admin or HR access is required.

### Permanent delete

Permanent delete removes the employee from memory completely.

```http
DELETE /api/employees/1?permanent=true
Authorization: Bearer YOUR_TOKEN
```

## Common Error Responses

### Missing token

```json
{
  "error": "Access token required",
  "message": "Please provide Bearer token in Authorization header"
}
```

### Employee not found

```json
{
  "error": "Employee not found",
  "message": "No employee found with ID: 999"
}
```

### Duplicate email

```json
{
  "error": "Email already exists"
}
```

## Status Codes

| Status | Meaning |
| --- | --- |
| `200` | Request succeeded |
| `201` | Employee created |
| `400` | Invalid request or missing required data |
| `401` | Authentication token is missing |
| `403` | Token is invalid or user lacks permission |
| `404` | Employee was not found |
| `409` | Email already exists |

For `GET /api/employees`, a query that matches no employees also returns `404`:

```json
{
  "success": false,
  "error": "No employees found",
  "message": "No employees matched the supplied search criteria",
  "data": [],
  "pagination": {
    "currentPage": 1,
    "totalPages": 0,
    "totalEmployees": 0,
    "limit": 10
  }
}
```
