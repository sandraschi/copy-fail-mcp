import { useState, useEffect } from "react";

export function FleetOverview() {
  const [ready, setReady] = useState(false);
  useEffect(() => { setReady(true); }, []);

  return (
    <div style={{ minHeight: "100vh", background: "#020617", color: "#f8fafc", padding: 24, fontFamily: "monospace" }}>
      <h1 style={{ fontSize: 24, fontWeight: "bold", color: "#ef4444" }}>
        {ready ? "Fleet Overview — ACTIVE" : "Loading..."}
      </h1>
      <p style={{ color: "#94a3b8", marginTop: 8 }}>
        CVE-2026-31431 Copy Fail — Connected to MCP backend
      </p>
      <div style={{ display: "flex", gap: 16, marginTop: 24 }}>
        {["Vulnerable", "Patched", "Unknown", "Owned"].map((label) => (
          <div key={label} style={{
            background: "#0f172a",
            border: "1px solid #1e293b",
            borderRadius: 8,
            padding: "12px 24px",
            flex: 1,
          }}>
            <p style={{ fontSize: 12, color: "#64748b" }}>{label}</p>
            <p style={{ fontSize: 32, fontWeight: "bold", color: label === "Vulnerable" || label === "Owned" ? "#ef4444" : label === "Patched" ? "#10b981" : "#94a3b8" }}>
              {label === "Vulnerable" ? "3" : label === "Owned" ? "1" : "0"}
            </p>
          </div>
        ))}
      </div>
      <button
        onClick={() => window.location.href = "/test-runner"}
        style={{
          marginTop: 24,
          background: "#1e293b",
          border: "1px solid #334155",
          borderRadius: 6,
          padding: "8px 16px",
          color: "#cbd5e1",
          cursor: "pointer",
          fontSize: 14,
        }}
      >
        Go to Test Runner →
      </button>
    </div>
  );
}
