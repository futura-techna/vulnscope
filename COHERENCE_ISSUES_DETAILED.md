# VulnScope Coherence Analysis - Issues & Fixes

## Issue Priority Matrix

```
                         IMPACT
                    Low      High
        CRITICAL    P2       P0* ← Password Reset
E       -------     --       --
A       HIGH        P2       P1* ← Dashboard Fallback
S                   --       --
E       MEDIUM      P2       P2* ← Status Casing
        
        * BLOCKING DEPLOYMENT
```

---

## Detailed Issues

### 🔴 P0-CRITICAL: Password Reset Routes Missing

**ID:** COHERENCE-001  
**Severity:** 🔴 CRITICAL  
**Status:** ❌ NOT WORKING  
**Effort:** 15 min  
**Impact:** 🚫 DEPLOYMENT BLOCKER

**Description:**
Frontend pages for password reset exist but have no backend route handlers. Users clicking "Forgot Password" or trying to reset will get 404 errors.

**Files Affected:**
1. [frontend/app/forgot-password/page.tsx](frontend/app/forgot-password/page.tsx#L31)
   ```typescript
   // Line 31
   const response = await fetch('/api/auth/forgot-password', {})
   // ❌ NO ROUTE HANDLER AT THIS PATH
   ```

2. [frontend/app/reset-password/page.tsx](frontend/app/reset-password/page.tsx#L52)
   ```typescript
   // Line 52
   const response = await fetch('/api/auth/reset-password', {})
   // ❌ NO ROUTE HANDLER AT THIS PATH
   ```

3. [frontend/lib/api.ts](frontend/lib/api.ts#L334-L340)
   ```typescript
   // Lines 334-340
   async requestPasswordReset(email: string): Promise<{ sent: boolean; message: string }> {
     const response = await this.client.post('/auth/forgot-password', { email })
     // ❌ WRONG ENDPOINT
   }

   async resetPassword(token: string, newPassword: string): Promise<{ success: boolean; message: string }> {
     const response = await this.client.post('/auth/reset-password', { token, new_password: newPassword })
     // ❌ WRONG ENDPOINT
   }
   ```

**What Exists:**
```
Backend:
  ✅ POST /auth/password-reset        (at src/api/auth_routes.py:385)
  ✅ POST /auth/password-reset/confirm (at src/api/auth_routes.py:415)

Next.js Routes:
  ✅ frontend/app/api/auth/password-reset/route.ts
  ✅ frontend/app/api/auth/password-reset/confirm/route.ts

Frontend Pages:
  ✅ frontend/app/forgot-password/page.tsx
  ✅ frontend/app/reset-password/page.tsx
```

**What's Missing:**
```
Next.js Routes:
  ❌ frontend/app/api/auth/forgot-password/route.ts
  ❌ frontend/app/api/auth/reset-password/route.ts
```

**Solution:**

**Option A:** Create Missing Route Handlers (RECOMMENDED)

Create `frontend/app/api/auth/forgot-password/route.ts`:
```typescript
import { NextRequest, NextResponse } from 'next/server'

export async function POST(request: NextRequest) {
  const apiUrl = process.env.API_URL || 'http://localhost:8000'
  const body = await request.json()

  const res = await fetch(`${apiUrl}/auth/password-reset`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  })

  const data = await res.json()
  return NextResponse.json(data, { status: res.status })
}
```

Create `frontend/app/api/auth/reset-password/route.ts`:
```typescript
import { NextRequest, NextResponse } from 'next/server'

export async function POST(request: NextRequest) {
  const apiUrl = process.env.API_URL || 'http://localhost:8000'
  const body = await request.json()

  const res = await fetch(`${apiUrl}/auth/password-reset/confirm`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  })

  const data = await res.json()
  return NextResponse.json(data, { status: res.status })
}
```

**Option B:** Update API Client
Update [frontend/lib/api.ts](frontend/lib/api.ts#L334-L340):
```typescript
async requestPasswordReset(email: string): Promise<{ sent: boolean; message: string }> {
  const response = await this.client.post('/auth/password-reset', { email })  // Changed endpoint
  return response.data
}

async resetPassword(token: string, newPassword: string): Promise<{ success: boolean; message: string }> {
  const response = await this.client.post('/auth/password-reset/confirm', { 
    token, 
    new_password: newPassword 
  })  // Changed endpoint
  return response.data
}
```

**Recommendation:** Use Option A (create route handlers) as it maintains consistent naming.

**Testing:**
```bash
# Test forgot password
curl -X POST http://localhost:3000/api/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com"}'

# Test reset password
curl -X POST http://localhost:3000/api/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{"token":"abc123","new_password":"NewPass123!"}'
```

---

### 🟡 P1-HIGH: Dashboard Stats Fallback Uses Random Values

**ID:** COHERENCE-002  
**Severity:** 🟡 MEDIUM  
**Status:** ⚠️ PARTIALLY WORKING  
**Effort:** 10 min  
**Impact:** ⚠️ Unreliable metrics without database

**Description:**
Dashboard stats endpoint calculates intelligent change values when using database, but falls back to random values when database is unavailable. This causes inconsistent metrics.

**Location:** [src/api/routes.py](src/api/routes.py#L65-L160)

**Current Code (BROKEN FALLBACK):**
```python
# Lines 153-160
return {
    "total_scans": total_scans,
    "active_scans": active_scans,
    "total_findings": total_findings,
    "critical_findings": critical_findings,
    "high_findings": high_findings,
    "medium_findings": medium_findings,
    "low_findings": low_findings,
    "total_targets": len(_targets_db),
    "scans_change": random.randint(-5, 15),          # ❌ RANDOM
    "critical_change": random.randint(-3, 2),        # ❌ RANDOM
    "high_change": random.randint(-5, 10),           # ❌ RANDOM
}
```

**Database Code (CORRECT):**
```python
# Lines 146-152 (working correctly)
scans_change = completed_scans - active_scans if total_scans > 0 else 0
critical_change = critical_findings // max(1, (total_findings // 10)) - 5 if total_findings > 0 else 0
high_change = high_findings - (critical_findings // 2) if total_findings > 0 else 0
```

**Solution:**

Replace random values with intelligent calculations:

```python
# Lines 153-160 (FIXED)
completed_scans = sum(1 for s in _scans_db.values() if s.status == Status.COMPLETED)
scans_change = completed_scans - active_scans if total_scans > 0 else 0
critical_change = critical_findings // max(1, (total_findings // 10)) - 5 if total_findings > 0 else 0
high_change = high_findings - (critical_findings // 2) if total_findings > 0 else 0

return {
    "total_scans": total_scans,
    "active_scans": active_scans,
    "total_findings": total_findings,
    "critical_findings": critical_findings,
    "high_findings": high_findings,
    "medium_findings": medium_findings,
    "low_findings": low_findings,
    "total_targets": len(_targets_db),
    "scans_change": scans_change,              # ✅ INTELLIGENT
    "critical_change": critical_change,        # ✅ INTELLIGENT
    "high_change": high_change,                # ✅ INTELLIGENT
}
```

---

### 🟡 P2-MEDIUM: Status Enum Case Sensitivity

**ID:** COHERENCE-003  
**Severity:** 🟡 MEDIUM  
**Status:** ⚠️ MITIGATED  
**Effort:** 30 min  
**Impact:** 📋 Code quality issue

**Description:**
Status values are inconsistent across different parts of the system:
- Core models use UPPERCASE: `PENDING`, `RUNNING`, `COMPLETED`
- Database stores lowercase: `pending`, `running`, `completed`
- Frontend expects Title Case: `Pending`, `Running`, `Completed`

Frontend uses `.toLowerCase()` normalization, which works but is fragile.

**Files Affected:**
1. [src/core/models.py](src/core/models.py#L22-28) - Uppercase
   ```python
   class Status(str, Enum):
       PENDING = "PENDING"
       RUNNING = "RUNNING"
       COMPLETED = "COMPLETED"
       FAILED = "FAILED"
       CANCELLED = "CANCELLED"
   ```

2. [src/database.py](src/database.py#L95) - Lowercase default
   ```python
   status = Column(String(50), default="pending")
   ```

3. [frontend/lib/api.ts](frontend/lib/api.ts#L30) - Title case type
   ```typescript
   status: 'Pending' | 'Running' | 'Completed' | 'Failed' | 'Cancelled'
   ```

4. [frontend/components/pages/Scans.tsx](frontend/components/pages/Scans.tsx#L84) - Workaround
   ```typescript
   switch (status?.toLowerCase()) { ... }
   ```

**Solution:**

Standardize to lowercase everywhere (simplest approach):

1. Update core models:
```python
class Status(str, Enum):
    PENDING = "pending"           # Changed
    RUNNING = "running"           # Changed
    COMPLETED = "completed"       # Changed
    FAILED = "failed"             # Changed
    CANCELLED = "cancelled"       # Changed
```

2. Update frontend types:
```typescript
status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
```

3. Remove workarounds:
```typescript
// Before
switch (status?.toLowerCase()) { ... }

// After
switch (status) { ... }
```

---

### 🔵 P3-LOW: Evidence Field Storage Type

**ID:** COHERENCE-004  
**Severity:** 🔵 LOW  
**Status:** ✅ ACCEPTABLE  
**Effort:** 20 min  
**Impact:** 📋 Optimization for future

**Description:**
Evidence field is stored as TEXT (JSON string) instead of native JSON type. Works correctly but loses benefits of JSON queries.

**Location:** [src/database.py](src/database.py#L159)

**Current:**
```python
evidence = Column(Text, nullable=True)
```

**Better:**
```python
evidence = Column(JsonType, default=dict)
```

**Note:** Low priority - can be improved incrementally

---

## Implementation Checklist

### Immediate (Before Deployment)
- [ ] **CRITICAL:** Create password reset route handlers
  - [ ] Create `frontend/app/api/auth/forgot-password/route.ts`
  - [ ] Create `frontend/app/api/auth/reset-password/route.ts`
  - [ ] Test forgot-password flow
  - [ ] Test reset-password flow
  - [ ] Verify email sent to user
  - **Effort:** 15 minutes

- [ ] **HIGH:** Fix dashboard fallback stats
  - [ ] Replace random values with calculations
  - [ ] Test without database connection
  - [ ] Verify metrics are consistent
  - **Effort:** 10 minutes

### Post-Deployment
- [ ] **MEDIUM:** Standardize status casing
  - [ ] Update core models to lowercase
  - [ ] Update frontend types to lowercase
  - [ ] Remove `.toLowerCase()` calls
  - [ ] Test all status-dependent features
  - **Effort:** 30 minutes

- [ ] **LOW:** Improve evidence JSON storage
  - [ ] Use JsonType column
  - [ ] Update serialization logic
  - [ ] Test evidence queries
  - **Effort:** 20 minutes

---

## Risk Assessment

| Issue | Risk | Mitigation | Priority |
|-------|------|-----------|----------|
| Password Reset Missing | HIGH - Feature broken | Create 2 route handlers | P0 |
| Dashboard Random Fallback | LOW - Works with DB | Fix fallback logic | P1 |
| Status Casing | LOW - Normalized in code | Standardize enum values | P2 |
| Evidence Storage Type | VERY LOW - Works fine | Use JSON type later | P3 |

---

## Testing Strategy

### Unit Tests
- [ ] Password reset endpoint
- [ ] Dashboard stats calculation
- [ ] Status enum values

### Integration Tests
- [ ] Complete password reset flow end-to-end
- [ ] Dashboard stats with and without database
- [ ] Settings persistence

### User Acceptance Tests
- [ ] Forgot password → Email → Reset password
- [ ] Settings can be saved and retrieved
- [ ] Dashboard shows correct stats

---

## Sign-Off

**Analysis Completed:** March 29, 2026  
**Analyst:** GitHub Copilot  
**Status:** Ready for fixing issues  
**Deployment Ready:** After P0 fixes
