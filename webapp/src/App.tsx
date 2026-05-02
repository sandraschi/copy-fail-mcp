import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AppLayout } from "@/components/layout/app-layout";
import { ErrorBoundary } from "@/common/error-boundary";
import { Targets } from "@/pages/targets";
import { TestRunner } from "@/pages/dashboard";
import { History } from "@/pages/history";
import { Help } from "@/pages/help";
import { About } from "@/pages/about";

export default function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <AppLayout>
          <Routes>
            <Route path="/" element={<Targets />} />
            <Route path="/test-runner" element={<TestRunner />} />
            <Route path="/history" element={<History />} />
            <Route path="/help" element={<Help />} />
            <Route path="/about" element={<About />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </AppLayout>
      </BrowserRouter>
    </ErrorBoundary>
  );
}
