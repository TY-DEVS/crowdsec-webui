# Multi-Instance Decision Propagation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable security analysts to select any subset of CrowdSec instances when creating decisions and propagate active decisions across the fleet with a single click.

**Architecture:** Extend backend instance resolution to support `scope: 'selected'` with `instance_ids: string[]`, upgrade `AddDecisionModal` with a flexible instance targeting control (current, all, or custom checkboxes) and scenario intersection, and add a "Propagate to Fleet" row action in `Decisions.tsx` and `Alerts.tsx`.

**Tech Stack:** TypeScript, Hono, React 19, Tailwind CSS v4, Lucide icons, Vitest.

## Global Constraints

- Must maintain strict backwards compatibility with existing `scope: 'all'` and `scope: 'instance'` endpoints.
- Allowlist pre-flight checks must evaluate all selected target instances concurrently.
- Differing manual decision scenarios across selected instances must fall back to `DEFAULT_MANUAL_DECISION_SCENARIO`.
- All changes must pass `tsc --noEmit`, ESLint, and Vitest tests.

---

### Task 1: Update Shared Contracts

**Files:**
- Modify: `shared/contracts.ts:869-879`

**Interfaces:**
- Consumes: None
- Produces: `AddDecisionRequest.scope` supporting `'selected'`, and `AddDecisionRequest.instance_ids?: string[]`.

- [x] **Step 1: Update AddDecisionRequest interface**

Update `AddDecisionRequest` in `shared/contracts.ts`:
```typescript
export interface AddDecisionRequest {
  ip: string;
  duration?: string;
  reason?: string;
  type?: 'ban' | 'captcha';
  scenario?: string;
  scope?: 'all' | 'instance' | 'selected';
  instance_id?: string;
  instance_ids?: string[];
  /** LAPI trusts decisions sent with an alert, so allowlists are checked here unless this is set. */
  bypass_allowlist?: boolean;
}
```

- [x] **Step 2: Verify typecheck**

Run: `pnpm run typecheck`  
Expected: PASS

- [x] **Step 3: Commit**

```bash
git add shared/contracts.ts
git commit -m "feat(shared): add selected scope and instance_ids to AddDecisionRequest"
```

---

### Task 2: Backend Target Resolution & API Routes

**Files:**
- Modify: `server/app.ts:1685-1691`
- Modify: `server/app/api-routes.ts:1640-1645, 1734-1738`
- Test: `server/__tests__/app/api-decisions-propagation.test.ts`

**Interfaces:**
- Consumes: `AddDecisionRequest.scope`, `AddDecisionRequest.instance_ids`
- Produces: Updated `resolveOperationInstances` supporting `scope: 'selected'` and array of targets.

- [x] **Step 1: Write the failing backend test**

Create `server/__tests__/app/api-decisions-propagation.test.ts` testing:
1. `resolveOperationInstances` with `scope: 'selected'` and valid `instance_ids`.
2. `resolveOperationInstances` with invalid `instance_ids` returning error.
3. `/api/decisions` endpoint receiving `scope: 'selected'` and `instance_ids`.

- [x] **Step 2: Run test to verify it fails**

Run: `pnpm exec vitest run server/__tests__/app/api-decisions-propagation.test.ts`  
Expected: FAIL

- [x] **Step 3: Update resolveOperationInstances and api-routes**

In `server/app.ts`:
```typescript
function resolveOperationInstances(
  scope: 'all' | 'instance' | 'selected' | undefined,
  instanceId: string | undefined,
  instanceIds?: string[],
) {
  if (!scope) return [primaryInstance];
  if (scope === 'all') return config.instances;
  if (scope === 'selected' || (instanceIds && instanceIds.length > 0)) {
    const ids = new Set(instanceIds || []);
    const matching = config.instances.filter((candidate) => ids.has(candidate.id));
    return matching.length > 0
      ? matching
      : { error: 'At least one valid instance_id is required when scope is selected' };
  }
  const instance = config.instances.find((candidate) => candidate.id === instanceId);
  return instance ? [instance] : { error: 'A valid instance_id is required when scope is instance' };
}
```

In `server/app/api-routes.ts`:
Pass `body.instance_ids` into `resolveOperationInstances(body.scope, body.instance_id, body.instance_ids)` in both `/api/decisions` and `/api/decisions/bulk-add`.

- [x] **Step 4: Run test to verify it passes**

Run: `pnpm exec vitest run server/__tests__/app/api-decisions-propagation.test.ts`  
Expected: PASS

- [x] **Step 5: Commit**

```bash
git add server/app.ts server/app/api-routes.ts server/__tests__/app/api-decisions-propagation.test.ts
git commit -m "feat(server): support selected scope and instance_ids in decision routes"
```

---

### Task 3: Localization Keys

**Files:**
- Modify: `client/src/locales/en.json`

**Interfaces:**
- Consumes: None
- Produces: UI translation keys for fleet decision propagation and target instance selection.

- [x] **Step 1: Add translation strings**

Add keys under `pages.decisions`:
- `propagateToFleet`: "Propagate ban to fleet"
- `targetScope`: "Target Instances"
- `targetScopeCurrent`: "Current Instance"
- `targetScopeAll`: "All Instances ({{count}})"
- `targetScopeCustom`: "Select Instances"
- `selectAll`: "Select All"
- `deselectAll`: "Deselect All"
- `targetInstancesSelected`: "Targeting {{count}} of {{total}} instances: {{names}}"

- [x] **Step 2: Commit**

```bash
git add client/src/locales/en.json
git commit -m "feat(i18n): add translations for fleet decision propagation"
```

---

### Task 4: AddDecisionModal Multi-Instance Targeting Enhancement

**Files:**
- Modify: `client/src/components/AddDecisionModal.tsx`
- Test: `client/src/components/__tests__/AddDecisionModal.test.tsx`

**Interfaces:**
- Consumes: `instances: CrowdsecInstanceConfig[]`, `multipleInstances: boolean`, `currentInstanceId?: string`, `defaultAllInstances?: boolean`
- Produces: Interactive instance target selection (current, all, or custom checkboxes), combined allowlist check across all targets, scenario intersection fallback.

- [x] **Step 1: Write failing component test**

Add tests to verify:
1. When `multipleInstances` is true, renders target selector.
2. Selecting custom instances toggles checkboxes and includes their IDs in the submit payload.
3. Allowlist check evaluates across all selected instance IDs.

- [x] **Step 2: Run test to verify it fails**

Run: `pnpm exec vitest run client/src/components/__tests__/AddDecisionModal.test.tsx`  
Expected: FAIL

- [x] **Step 3: Implement targeting controls in AddDecisionModal**

Refactor `AddDecisionModal.tsx`:
- Maintain `targetMode: 'current' | 'all' | 'custom'`.
- Maintain `selectedInstanceIds: Set<string>`.
- Render segmented buttons or pills: `Current`, `All (N)`, `Custom`.
- When `Custom`, render checkboxes for each instance with Select All / Deselect All.
- Update `submit()` and `submitBulk()` to pass `scope: targetMode === 'all' ? 'all' : targetMode === 'custom' ? 'selected' : 'instance'` and `instance_ids: Array.from(selectedInstanceIds)`.
- Update `allowlistScope` to pass `'all'` when in `all` or `custom` mode with $>1$ instance, or the single instance ID when only 1 instance is selected.

- [x] **Step 4: Run test to verify it passes**

Run: `pnpm exec vitest run client/src/components/__tests__/AddDecisionModal.test.tsx`  
Expected: PASS

- [x] **Step 5: Commit**

```bash
git add client/src/components/AddDecisionModal.tsx client/src/components/__tests__/AddDecisionModal.test.tsx
git commit -m "feat(client): add granular multi-instance selector to AddDecisionModal"
```

---

### Task 5: Decisions Table Fleet Propagation Action

**Files:**
- Modify: `client/src/pages/Decisions.tsx`
- Test: `client/src/pages/__tests__/decisions/actions.test.tsx`

**Interfaces:**
- Consumes: Decision row data (`value`, `duration`, `scenario`, `message`, `instance_id`)
- Produces: Action button with `Globe` icon that opens `AddDecisionModal` configured for fleet propagation.

- [x] **Step 1: Write test for propagate row action**

In `client/src/pages/__tests__/decisions/actions.test.tsx`:
- Test that when `multipleInstances` is true, an active decision row renders the "Propagate ban to fleet" button.
- Clicking the button opens `AddDecisionModal` with `defaultAllInstances={true}` and the IP pre-filled.

- [x] **Step 2: Run test to verify it fails**

Run: `pnpm exec vitest run client/src/pages/__tests__/decisions/actions.test.tsx`  
Expected: FAIL

- [x] **Step 3: Implement propagate row action in Decisions.tsx**

In `client/src/pages/Decisions.tsx`:
- Add `Globe` icon button in table row actions when `multipleInstances && canManageEnforcement && !isExpired`.
- On click, store `propagateDecision` state and open `AddDecisionModal`.

- [x] **Step 4: Run test to verify it passes**

Run: `pnpm exec vitest run client/src/pages/__tests__/decisions/actions.test.tsx`  
Expected: PASS

- [x] **Step 5: Commit**

```bash
git add client/src/pages/Decisions.tsx client/src/pages/__tests__/decisions/actions.test.tsx
git commit -m "feat(decisions): add propagate to fleet action button in decisions table"
```

---

### Task 6: Alerts Table Fleet Decision Propagation

**Files:**
- Modify: `client/src/pages/Alerts.tsx`
- Test: `client/src/pages/__tests__/alerts/details-and-actions.test.tsx`

**Interfaces:**
- Consumes: Alert decision trigger
- Produces: `AddDecisionModal` opened from alerts cleanly exposing fleet propagation options.

- [x] **Step 1: Verify and update Alerts.tsx integration**

Ensure `AddDecisionModal` invocation in `Alerts.tsx` supports the enhanced multi-instance controls without regressions.

- [x] **Step 2: Run Alerts tests**

Run: `pnpm exec vitest run client/src/pages/__tests__/alerts/details-and-actions.test.tsx`  
Expected: PASS

- [x] **Step 3: Commit**

```bash
git add client/src/pages/Alerts.tsx
git commit -m "feat(alerts): integrate enhanced fleet decision modal in alerts page"
```

---

### Task 7: Full Verification, Typecheck, and Build

**Files:** All modified files

- [x] **Step 1: Run TypeScript compiler**

Run: `pnpm run typecheck`  
Expected: Clean exit 0 with no errors.

- [x] **Step 2: Run ESLint**

Run: `pnpm run lint`  
Expected: Clean exit 0.

- [x] **Step 3: Run targeted test suite**

Run: `pnpm exec vitest run server/__tests__/app/api-decisions-propagation.test.ts client/src/components/__tests__/AddDecisionModal.test.tsx client/src/pages/__tests__/decisions/actions.test.tsx`  
Expected: All passing.

- [x] **Step 4: Run production build**

Run: `pnpm run build`  
Expected: Vite build + tsup finish successfully.
