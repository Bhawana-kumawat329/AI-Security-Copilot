import { useState } from "react";
import Dashboard from "./pages/Dashboard";
import AuthPage from "./pages/AuthPage";
import "./styles/dashboard.css";

function App() {
  const savedUser = localStorage.getItem("user");
  const [user, setUser] = useState(savedUser ? JSON.parse(savedUser) : null);

  const logout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    setUser(null);
  };

  if (!user) {
    return <AuthPage onLogin={setUser} />;
  }

  return (
    <>
      <button className="logout-btn" onClick={logout}>
        Logout
      </button>
      <Dashboard />
    </>
  );
}

export default App;
