import { useState } from "react";
import { NavLink, Outlet, useNavigate, useLocation } from "react-router-dom";
import {
  ShieldCheck,
  LayoutDashboard,
  Radio,
  Layers,
  Server,
  ScanLine,
  ChartNoAxesCombined,
  Sparkles,
  ScrollText,
  Settings,
  Users,
  Search,
  Bell,
  ChevronRight,
  Menu,
  X,
  LogOut,
  Sun,
  Moon,
  ChevronDown,
} from "lucide-react";
import { useAuth } from "../hooks/Auth";
import { useResource } from "../hooks/useResource";
import type { Settings as SettingsData } from "../types";
const mainNav = [
  ["/", "Overview", LayoutDashboard],
  ["/alerts", "Threat alerts", Radio],
  ["/incidents", "Incidents", Layers],
  ["/assets", "Assets", Server],
] as const;
const intelligenceNav = [
  ["/rules", "Detection rules", ScanLine],
  ["/analytics", "Threat analytics", ChartNoAxesCombined],
  ["/ai", "AI analyst", Sparkles],
] as const;
export function Layout() {
  const { user, logout } = useAuth(),
    navigate = useNavigate(),
    location = useLocation();
  const [open, setOpen] = useState(false),
    [search, setSearch] = useState(""),
    [error, setError] = useState(""),
    [light, setLight] = useState(
      localStorage.getItem("sentinel-theme") === "light",
    );
  const { data: settings } = useResource<SettingsData>("/settings");
  const title =
    [
      ...mainNav,
      ...intelligenceNav,
      ["/audit", "Audit logs"],
      ["/settings", "Settings"],
      ["/users", "User management"],
    ].find(
      (n) =>
        n[0] ===
        (location.pathname === "/"
          ? "/"
          : "/" + location.pathname.split("/")[1]),
    )?.[1] || "Investigation";
  return (
    <div className={`app-shell ${light ? "light" : ""}`}>
      <aside className={`sidebar ${open ? "open" : ""}`}>
        <LinkBrand />
        <button
          className="mobile-close icon-button"
          aria-label="Close navigation"
          onClick={() => setOpen(false)}
        >
          <X />
        </button>
        <div className="workspace">
          <div className="workspace-avatar">S</div>
          <div>
            <strong>Sentinel workspace</strong>
            <small>Security operations center</small>
          </div>
          <ChevronDown size={14} />
        </div>
        <p className="nav-label">WORKSPACE</p>
        <nav>
          {mainNav.map(([path, label, Icon]) => (
            <NavLink
              end={path === "/"}
              to={path}
              key={path}
              onClick={() => setOpen(false)}
            >
              <Icon size={18} />
              <span>{label}</span>
              {path === "/alerts" && <span className="nav-live" />}
            </NavLink>
          ))}
        </nav>
        <p className="nav-label">INTELLIGENCE</p>
        <nav>
          {intelligenceNav.map(([path, label, Icon]) => (
            <NavLink to={path} key={path} onClick={() => setOpen(false)}>
              <Icon size={18} />
              <span>{label}</span>
              {path === "/ai" && <span className="mini-tag">AI</span>}
            </NavLink>
          ))}
        </nav>
        <p className="nav-label">ADMINISTRATION</p>
        <nav>
          {user?.role === "admin" && (
            <>
              <NavLink to="/audit" onClick={() => setOpen(false)}>
                <ScrollText size={18} />
                Audit logs
              </NavLink>
              <NavLink to="/users" onClick={() => setOpen(false)}>
                <Users size={18} />
                User management
              </NavLink>
            </>
          )}
          <NavLink to="/settings" onClick={() => setOpen(false)}>
            <Settings size={18} />
            Settings
          </NavLink>
        </nav>
        <div className="sidebar-bottom">
          <div className="system-status">
            <span className="status-light" />
            <div>
              Detection engine<small>Deterministic · log analysis</small>
            </div>
            <span className="version">v1.0</span>
          </div>
          <div className="profile">
            <div className="avatar">{user?.name.slice(0, 2).toUpperCase()}</div>
            <div>
              <strong>{user?.name}</strong>
              <small>{user?.role} access</small>
            </div>
            <button
              className="icon-button"
              aria-label="Sign out"
              onClick={() => logout().catch((e) => setError(e.message))}
            >
              <LogOut size={17} />
            </button>
          </div>
          {error && <p className="text-danger">{error}</p>}
        </div>
      </aside>
      {open && <div className="sidebar-scrim" onClick={() => setOpen(false)} />}
      <div className="main-shell">
        <header className="topbar">
          <button
            className="mobile-menu icon-button"
            aria-label="Open navigation"
            onClick={() => setOpen(true)}
          >
            <Menu size={21} />
          </button>
          <div className="breadcrumb">
            <ShieldCheck size={16} />
            <span>Workspace</span>
            <ChevronRight size={14} />
            <strong>{title}</strong>
          </div>
          <div className="topbar-right">
            <form
              className="global-search"
              onSubmit={(e) => {
                e.preventDefault();
                navigate("/alerts?q=" + encodeURIComponent(search));
              }}
            >
              <Search size={15} />
              <input
                aria-label="Search threats"
                placeholder="Search threats, IPs, hosts…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              <kbd>↵</kbd>
            </form>
            <span className="environment-badge">
              <i />
              {settings?.demo_mode ? "DEMO LAB" : "LOCAL SOC"}
            </span>
            <button
              className="icon-button"
              aria-label="Toggle color theme"
              onClick={() => {
                setLight(!light);
                localStorage.setItem(
                  "sentinel-theme",
                  !light ? "light" : "dark",
                );
              }}
            >
              {light ? <Moon size={18} /> : <Sun size={18} />}
            </button>
            <button
              className="icon-button notification"
              aria-label="View new alerts"
              onClick={() => navigate("/alerts?status=New")}
            >
              <Bell size={18} />
              <i />
            </button>
          </div>
        </header>
        <main className="main-content">
          <Outlet />
        </main>
        <footer className="app-footer">
          <span>
            <ShieldCheck size={13} />
            SentinelAI · Built for defenders
          </span>
          <span>Authorized monitoring. Explainable intelligence.</span>
        </footer>
      </div>
    </div>
  );
}
export function LinkBrand() {
  return (
    <div className="brand">
      <span className="brand-mark">
        <ShieldCheck size={26} />
      </span>
      <span>
        Sentinel<span className="brand-ai">AI</span>
        <small>SECURITY OPERATIONS</small>
      </span>
    </div>
  );
}
