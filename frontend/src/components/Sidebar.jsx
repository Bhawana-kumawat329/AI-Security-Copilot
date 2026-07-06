function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="logo">AI</div>
        <div>
          <h2>Security Copilot</h2>
          <p>SOC Platform</p>
        </div>
      </div>

      <nav>
        <a className="active">Dashboard</a>
        <a>Threat Intel</a>
        <a>Network</a>
        <a>Vulnerabilities</a>
        <a>Reports</a>
        <a>History</a>
      </nav>
    </aside>
  );
}

export default Sidebar;
