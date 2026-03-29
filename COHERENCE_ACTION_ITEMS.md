# VulnScope Coherence Issues - Quick Action Items

## 🔴 CRITICAL - Must Fix Before Production

### 1. Missing Settings Endpoints (NULL_IMPLEMENTATION)
**Status:** ❌ Broken  
**Affected:** Settings page completely non-functional  
**Files:**
- Frontend: `frontend/components/pages/Settings.tsx` (lines 29-31)
- Backend: `src/api/routes.py` - No `/settings` endpoints

**What's needed:**
```python
# Add to src/api/routes.py

@router.get("/settings", tags=["settings"])
async def get_settings():
    """Get user settings"""
    # Return default settings for now
    return {
        "api_url": "http://localhost:8000",
        "max_concurrent": 10,
        "timeout": 30,
        "rate_limit": 100,
        "email_notifications": True,
        "slack_integration": False,
        "default_theme": "dark",
        "auto_refresh": False
    }

@router.put("/settings", tags=["settings"])
async def update_settings(settings: dict):
    """Update user settings"""
    # Store settings somewhere (database or session)
    return settings
```

**Effort:** 1-2 hours  
**Owner:** Backend developer

---

### 2. Finding Status Enum Mismatch
**Status:** ⚠️ Partially broken  
**Affected:** Finding filtering, status updates  
**Files:**
- Backend: `src/core/models.py` (line 26) & `src/api/routes.py` (line 1047)
- Frontend: `frontend/lib/api.ts` (line 70) & `frontend/components/pages/Findings.tsx`

**Problem:**
- Scan status: `"PENDING"`, `"RUNNING"`, `"COMPLETED"`, etc.
- Finding status: `"Open"`, `"In Progress"`, `"Resolved"`, `"False Positive"`
- These are incompatible enums!

**Solution:** Standardize to one enum. Options:
1. Use capitalized: `"Pending"`, `"Running"`, `"Completed"`, `"Failed"`, `"Cancelled"` for both
2. Use lowercase: All lowercase with underscores for backend, convert on API boundary

**Recommend:** Option 1 - Capitalized format (easier for UI)

**Effort:** 2-3 hours  
**Owner:** Full-stack

---

### 3. Compliance Response Structure Mismatch
**Status:** 🔴 Will crash  
**Affected:** Compliance page  
**Files:**
- Backend: `src/api/routes.py` (line 1722) returns `{"standards": [...]}`
- Frontend: `frontend/components/pages/Compliance.tsx` (line 56) expects array directly

**Current Backend:**
```python
return {"standards": standards}
```

**Frontend expects:**
```typescript
const { data: standardsData } = useCompliance()
// standardsData is the array directly, not {standards: array}
```

**Fix:** Remove wrapping in backend:
```python
# Change this:
return {"standards": standards}
# To this:
return standards  # Return array directly
```

**Effort:** 15 minutes  
**Owner:** Backend

---

## 🟠 HIGH - Fix in Week 1

### 4. WebSocket Not Integrated
**Status:** ❌ Not wired  
**Affected:** Real-time scan features  
**Files:**
- `src/api/websocket.py` - Defined but not used
- `src/api/main.py` - No WebSocket route added
- Frontend: No WebSocket client

**What's needed:**
```python
# In src/api/main.py, add after creating app:
from fastapi import WebSocket
from .websocket import ws_manager

@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle client messages if needed
    except Exception:
        ws_manager.disconnect(websocket)
```

**Effort:** 4-5 hours (including frontend client)  
**Owner:** Full-stack

---

### 5. Email Verification Incomplete
**Status:** ⚠️ Backend done, frontend missing  
**Affected:** User registration flow  
**Files:**
- Backend: `src/api/auth_routes.py` (lines 467-532) ✓ Done
- Frontend: Missing API methods in `frontend/lib/api.ts`
- Frontend: Missing component for `app/verify-email/page.tsx`

**What to add to frontend/lib/api.ts:**
```typescript
async verifyEmail(token: string): Promise<{ verified: boolean }> {
    const response = await this.client.post('/auth/verify-email', { token })
    return response.data
}

async resendVerificationEmail(email: string): Promise<{ sent: boolean }> {
    const response = await this.client.post('/auth/resend-verification', { email })
    return response.data
}
```

**Effort:** 3-4 hours  
**Owner:** Full-stack

---

### 6. Evidence Field Type Inconsistency
**Status:** ⚠️ May break JSON display  
**Affected:** Finding evidence display  
**Files:**
- Backend: `src/core/models.py` (line 151) - `evidence: Dict[str, Any]`
- Frontend: `frontend/lib/api.ts` (line 67) - treats as string

**Current issue:**
```typescript
// Frontend expects:
evidence?: string

// Backend returns:
"evidence": { "screenshot": "...", "http_response": "..." }
```

**Fix:** Update frontend interface:
```typescript
evidence?: Record<string, any>  // Change from string to object
```

**Effort:** 1 hour  
**Owner:** Frontend

---

## 🟡 MEDIUM - Fix in Week 2

### 7. Use Dashboard Stats Endpoint
**Status:** ⚠️ Performance issue  
**Affected:** Dashboard loading  
**Files:** `frontend/components/pages/Dashboard.tsx` (lines 58-75)

**Current:** Fetches targets, scans, findings separately then computes stats  
**Better:** Call `/dashboard/stats` endpoint once

```typescript
// Current (bad):
const { data: targets } = useTargets()
const { data: scans } = useScans()
const { data: findingsData } = useFindings({ limit: 100 })

// Better:
const { data: stats } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: () => api.getDashboardStats()
})
```

**Effort:** 2 hours  
**Owner:** Frontend

---

### 8. Calculate Real "Change" Values
**Status:** 🔴 Currently random  
**Affected:** Dashboard trends  
**Files:** `src/api/routes.py` (lines 156-160)

**Current (broken):**
```python
"scans_change": random.randint(-5, 15),  # Random every time!
```

**Needed:** Store historical data somewhere and calculate actual changes

**Workaround until history tracking:** Use the changes from actual data

**Effort:** 3-4 hours  
**Owner:** Backend

---

### 9. Wire Up Discovery Options
**Status:** ⚠️ Features ignored  
**Affected:** Scan flexibility  
**Files:**
- Frontend: `frontend/components/pages/Scans.tsx` (lines 21, 43-46)
- Backend: `src/api/routes.py` (scan creation) ignores the flags

**Current:** `enable_crawler`, `enable_openapi_import`, `enable_graphql_import` passed but ignored

**Need:** Actually call the discovery methods during scan execution

**Effort:** 4-5 hours  
**Owner:** Backend

---

## 🔵 LOW - Fix Later

### 10. Add Password Reset Page
**Status:** ✓ Backend ready, frontend missing  
**Files:**
- Backend: `src/api/auth_routes.py` (lines 385-413) ✓
- Frontend: Missing component

**Effort:** 2-3 hours  
**Owner:** Frontend

---

### 11. Add Report Pagination
**Status:** ⚠️ Works but not optimized  
**Files:** Frontend reports table shows all, no pagination UI

**Effort:** 1-2 hours  
**Owner:** Frontend

---

## Quick Test Checklist

### ✅ Before Committing Critical Fixes

- [ ] Settings page loads without 404 errors
- [ ] Finding status filters work and don't error
- [ ] Compliance page displays all standards correctly
- [ ] WebSocket connects during scan (check browser console)
- [ ] Email verification link works in email preview
- [ ] Evidence field renders as JSON (not broken string)

### ✅ Before Production Deployment

- [ ] All 4 critical issues fixed and tested
- [ ] Dashboard stats endpoint used
- [ ] At least 2 high-priority issues fixed
- [ ] No console errors in production build
- [ ] API tests pass for all modified endpoints
- [ ] Frontend E2E tests pass for critical pages

---

## Environment Setup for Testing

```bash
# Backend
cd /home/cisse/vulnscope
python -m pip install -r requirements.txt
python -m pytest

# Frontend
cd frontend
npm install
npm run dev

# Test API availability
curl http://localhost:8000/api/v1/health
```

---

## Severity Legend

🔴 **CRITICAL** - Breaks core functionality  
🟠 **HIGH** - Degrades user experience  
🟡 **MEDIUM** - Quality or performance issues  
🔵 **LOW** - Polish or nice-to-have features  

---

## Total Effort Estimate

| Phase | Issues | Hours | Timeline |
|-------|--------|-------|----------|
| Critical | 3 | 6-8 | This sprint |
| High | 3 | 10-12 | Next week |
| Medium | 3 | 8-10 | Following week |
| Low | 2 | 5-6 | As-needed |
| **TOTAL** | **11** | **29-36** | 3-4 weeks |

**If prioritizing critical only: 1 week to production-ready**

