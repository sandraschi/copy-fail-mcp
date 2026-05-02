import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AppLayout } from "@/components/layout/app-layout";
import { FleetOverview } from "@/pages/fleet-overview";
import { TestRunner } from "@/pages/dashboard";
import { History } from "@/pages/history";
import { Help } from "@/pages/help";
import { About } from "@/pages/about";

export default function App() {
  return (
    <BrowserRouter>
      <AppLayout>
        <Routes>
          <Route path="/" element={<FleetOverview />} />
          <Route path="/test-runner" element={<TestRunner />} />
          <Route path="/history" element={<History />} />
          <Route path="/help" element={<Help />} />
          <Route path="/about" element={<About />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AppLayout>
    </BrowserRouter>
  );
}
