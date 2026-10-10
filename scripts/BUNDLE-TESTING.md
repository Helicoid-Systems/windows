# Bundle tester quick start

Development-only launcher for the unsigned `helicoid-windows-unsigned-dev` bundle.

## Steps

1. **Close** any old Helicoid Manager window.
2. **Start** the development server (loopback `http://127.0.0.1:8787`).
3. **Double-click** `manager/start-development-manager.cmd`.
4. Confirm the **development badge** in the Manager window.
5. **Sign in** as `admin` using your **private password** (never committed or bundled).

The script launches the sibling `Helicoid.Manager.exe` with explicit flags only:

```
--development-server=http://127.0.0.1:8787 --development-manager-identity dev-manager-key
```

It does not embed credentials, does not enable production mode, and does not
install or configure any server or policy.

## Expected console-probe note

`Helicoid.ConsoleProbe` in the separate `helicoid-windows-console-probe`
artifact is a **working candidate diagnostic**, not production authorization.
