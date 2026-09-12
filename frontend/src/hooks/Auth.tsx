import { createContext, useContext, useEffect, useState } from "react";
import type { ReactNode } from "react";
import type { User } from "../types";
import { post, restoreSession, setToken } from "../services/api";
interface AuthState {
  user: User | null;
  ready: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}
const Context = createContext<AuthState | null>(null);
export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null),
    [ready, setReady] = useState(false);
  useEffect(() => {
    restoreSession()
      .then(setUser)
      .finally(() => setReady(true));
    const expire = () => setUser(null);
    window.addEventListener("session-expired", expire);
    return () => window.removeEventListener("session-expired", expire);
  }, []);
  async function login(email: string, password: string) {
    const data = await post<{ user: User; access_token: string }>(
      "/auth/login",
      { email, password },
    );
    setToken(data.access_token);
    setUser(data.user);
  }
  async function logout() {
    await post("/auth/logout");
    setToken(null);
    setUser(null);
  }
  return (
    <Context.Provider value={{ user, ready, login, logout }}>
      {children}
    </Context.Provider>
  );
}
export function useAuth() {
  const context = useContext(Context);
  if (!context) throw new Error("AuthProvider required");
  return context;
}
