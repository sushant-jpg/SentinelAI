import {
  BrowserRouter,
  Routes,
  Route,
  Navigate,
  Outlet,
} from "react-router-dom";
import { AuthProvider, useAuth } from "./hooks/Auth";
import { Layout } from "./components/Layout";
import { Loading, Empty } from "./components/ui";
import { Login } from "./pages/Login";
import { Dashboard } from "./pages/Dashboard";
import { Alerts } from "./pages/Alerts";
import { AlertDetails, IncidentDetails } from "./pages/Details";
import { Incidents, Assets, Rules } from "./pages/Operations";
import { Analytics, AIAnalysis } from "./pages/Intelligence";
import { AuditLogs, Users, Settings } from "./pages/Admin";
function Protected() {
  const { user, ready } = useAuth();
  return !ready ? (
    <Loading />
  ) : user ? (
    <Outlet />
  ) : (
    <Navigate to="/login" replace />
  );
}
function AdminOnly() {
  const { user } = useAuth();
  return user?.role === "admin" ? <Outlet /> : <Navigate to="/" replace />;
}
export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route element={<Protected />}>
            <Route element={<Layout />}>
              <Route index element={<Dashboard />} />
              <Route path="alerts" element={<Alerts />} />
              <Route path="alerts/:id" element={<AlertDetails />} />
              <Route path="incidents" element={<Incidents />} />
              <Route path="incidents/:id" element={<IncidentDetails />} />
              <Route path="assets" element={<Assets />} />
              <Route path="rules" element={<Rules />} />
              <Route path="analytics" element={<Analytics />} />
              <Route path="ai" element={<AIAnalysis />} />
              <Route path="settings" element={<Settings />} />
              <Route element={<AdminOnly />}>
                <Route path="audit" element={<AuditLogs />} />
                <Route path="users" element={<Users />} />
              </Route>
              <Route
                path="*"
                element={
                  <Empty
                    title="Page not found"
                    text="Choose a workspace page from the navigation."
                  />
                }
              />
            </Route>
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
