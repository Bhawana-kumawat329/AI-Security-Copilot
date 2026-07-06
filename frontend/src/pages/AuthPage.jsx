import { useState } from "react";
import axios from "axios";

const API = "http://127.0.0.1:8000";

function AuthPage({ onLogin }) {
  const [mode, setMode] = useState("login");
  const [form, setForm] = useState({
    name: "",
    email: "",
    password: "",
  });

  const submit = async () => {
    if (!form.email || !form.password) {
      alert("Email and password required");
      return;
    }

    if (mode === "signup" && !form.name) {
      alert("Name required");
      return;
    }

    try {
      const url = mode === "login" ? "/api/auth/login" : "/api/auth/signup";

      const payload =
        mode === "login"
          ? { email: form.email, password: form.password }
          : form;

      const res = await axios.post(`${API}${url}`, payload);

      if (!res.data.success) {
        alert(res.data.message);
        return;
      }

      if (mode === "signup") {
        alert("Signup successful. Now login.");
        setMode("login");
        return;
      }

      localStorage.setItem("token", res.data.access_token);
      localStorage.setItem("user", JSON.stringify(res.data.user));
      onLogin(res.data.user);
    } catch (err) {
      alert("Auth API error. Backend running hai ya nahi check karo.");
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <h1>AI Security Copilot</h1>
        <p>{mode === "login" ? "Login to SOC Dashboard" : "Create your analyst account"}</p>

        {mode === "signup" && (
          <input
            type="text"
            placeholder="Full Name"
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
          />
        )}

        <input
          type="email"
          placeholder="Email"
          value={form.email}
          onChange={(e) => setForm({ ...form, email: e.target.value })}
        />

        <input
          type="password"
          placeholder="Password"
          value={form.password}
          onChange={(e) => setForm({ ...form, password: e.target.value })}
        />

        <button onClick={submit}>
          {mode === "login" ? "Login" : "Create Account"}
        </button>

        <span onClick={() => setMode(mode === "login" ? "signup" : "login")}>
          {mode === "login"
            ? "New user? Create account"
            : "Already have account? Login"}
        </span>
      </div>
    </div>
  );
}

export default AuthPage;
