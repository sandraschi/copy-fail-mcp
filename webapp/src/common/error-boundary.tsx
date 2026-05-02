import { Component, type ReactNode, type ErrorInfo } from "react";

interface Props { children: ReactNode; }
interface State { hasError: boolean; error: Error | null; }

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("App crash:", error, info.componentStack);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          minHeight: "100vh",
          background: "#020617",
          color: "#f8fafc",
          padding: 40,
          fontFamily: "monospace",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
        }}>
          <div style={{ fontSize: 48, marginBottom: 16, color: "#ef4444" }}>!</div>
          <h1 style={{ fontSize: 20, fontWeight: "bold", color: "#ef4444", marginBottom: 8 }}>
            Something went wrong
          </h1>
          <p style={{ color: "#94a3b8", marginBottom: 24, maxWidth: 500, textAlign: "center", fontSize: 13 }}>
            {this.state.error?.message || "Unknown error"}
          </p>
          <button onClick={() => { this.setState({ hasError: false, error: null }); window.location.href = "/"; }}
            style={{
              background: "#1e293b", border: "1px solid #334155", borderRadius: 6,
              padding: "8px 20px", color: "#cbd5e1", cursor: "pointer", fontSize: 13,
            }}>
            Reload
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
