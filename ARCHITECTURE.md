# NetFabric Architecture

## Module Structure

```
backend/
  drivers/            ← ND layer       — vendor protocol, one file per vendor
  service_manager/    ← SM layer       — generic service orchestration
  device_manager/     ← DM layer       — device inventory & sync
  main.py             ← API layer      — thin FastAPI endpoints, calls the managers
```

`main.py` is routing only — no business logic lives there. Each manager is independently testable and extendable.

---

## ND Layer — Network Drivers (`backend/drivers/`)

Each ND (Network Driver) is a vendor-specific Python module that owns everything related to one platform's CLI dialect.

| File | ND ID | Platform |
|------|-------|----------|
| `cisco_ios_xe.py` | `cisco-ios-cli-1.0` | Cisco IOS-XE (routers, switches, ASR, CSR) |
| `fortigate.py` | `fortinet-fortios-cli-1.0` | Fortinet FortiGate (FortiOS 6.x / 7.x) |

### What each ND owns
- `cli_to_template(raw_cli)` — convert pasted CLI to YANG schema + Jinja2 template
- `validate_vars(values, schema_yaml)` — validate variable values (vendor-specific rules)
- `normalize_for_diff(config)` — strip volatile lines before comparing configs
- `parse_interface_names(raw)` — extract interface list from show output
- `test_command()`, `save_config_command()` — device lifecycle commands

### Shared helpers (`base.py`)
- `_infer_spec(key, value)` — infer YANG type from a default value
- `validate_var_value(key, value, spec)` — YANG type checker (used by all NDs)
- `render_var_form(schema_yaml)` — render YANG schema as typed HTML form fields
- `_schema_to_yaml(vars_dict)` — serialise variable dict to YANG YAML

### Adding a new vendor ND
1. Create `backend/drivers/<vendor>.py`
2. Subclass `BaseDriver`, set `NED_ID` / `NED_VERSION` / `PROTOCOL`
3. Implement `cli_to_template()` and optionally `validate_vars()`
4. Register in `backend/drivers/__init__.py`

---

## Service Manager (`backend/service_manager/manager.py`)

The Service Manager is the orchestration layer between the abstract service definition and the ND layer.

### Key concepts
- **Service** — generic, multi-vendor. Has one shared YANG variable schema and one Jinja2 template per supported ND stored in `nd_templates`.
- **nd_templates** — `{"cisco-ios-cli-1.0": "...", "fortinet-fortios-cli-1.0": "..."}` stored per service in the DB.
- At deploy time the Service Manager resolves `nd_templates[device.ned_id]` and renders it.

### Methods
| Method | Description |
|--------|-------------|
| `resolve_template(service, nd_id)` | Pick the right template for a device's ND |
| `render(service, device, var_values)` | Render Jinja2 template → CLI text |
| `dry_run(service, device, var_values, current_config)` | Render + diff against live config |
| `validate(service, device, var_values)` | Validate vars through the device's ND |
| `merge_schemas(base_yaml, new_yaml)` | Merge two YANG schemas (used when adding a new ND template) |

### Service lifecycle
```
Developer creates service:
  1. Name + description
  2. Paste IOS-XE CLI → ND converts → IOS-XE template + shared schema stored
  3. Paste FortiGate CLI → ND converts → FortiGate template + schema merged

Operator deploys service to device r1 (IOS-XE):
  Service Manager → nd_templates["cisco-ios-cli-1.0"] → render → ND pushes CLI

Operator deploys same service to fw1 (FortiGate):
  Service Manager → nd_templates["fortinet-fortios-cli-1.0"] → render → ND pushes CLI
```

---

## Device Manager (`backend/device_manager/manager.py`)

The Device Manager owns all operations that read from or write to the device database and live device state.

### Methods
| Method | Description |
|--------|-------------|
| `get_owned(device_id, user_id, db)` | Fetch device with ownership check |
| `resolve_credentials(device, db)` | Authgroup → plaintext username/password |
| `fetch_config(device, db)` | SSH pull running config |
| `fetch_interfaces(device, db)` | SSH pull interface list |
| `test_connectivity(device, db)` | SSH connectivity + version check |
| `sync_from(device, db)` | Pull config + store snapshot + update sync status |
| `acquire_lock(device_id, user_id, db)` | Exclusive write lock (returns txn_id) |
| `release_lock(device_id, txn_id, db)` | Release lock |
| `live_status(device, command_key, db)` | Run a live-status command and return output (e.g. routes, ARP, sessions) |

---

## API Layer (`backend/main.py`)

Thin FastAPI routing layer. Each endpoint:
1. Authenticates the user
2. Calls the appropriate manager
3. Returns the response

No business logic, no direct `device_connector` calls, no inline Jinja2 rendering.

---

## Data Flow

```
POST /api/services/{id}/deploy
  │
  ├─ main.py: auth, load service + device from DB
  ├─ ServiceManager.render(service, device, vars)
  │    └─ resolves nd_templates[device.ned_id]
  │    └─ Jinja2 render → CLI text
  ├─ DeviceManager.acquire_lock(device_id)
  ├─ device_connector.apply_config_set(host, cli_lines)
  └─ DeviceManager.sync_from(device)  ← auto-snapshot after deploy
```

---

## Validation Flow

```
User types in deploy form → onblur
  → POST /api/services/{id}/validate-vars {values, device_id}
  → ServiceManager.validate(service, device, values)
  → device.ned_id ND driver.validate_vars(values, schema)
  → validate_var_value() per field (YANG type rules + vendor overrides)
  → {errors: {field: message}} → frontend displays NDs message
```
