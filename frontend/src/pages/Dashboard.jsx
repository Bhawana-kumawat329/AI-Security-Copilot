import { useState } from "react";
import axios from "axios";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  ResponsiveContainer,
} from "recharts";

const API = "http://127.0.0.1:8000";

const COLORS = ["#ef4444", "#f59e0b", "#10b981", "#64748b", "#2563eb"];

function Dashboard() {
  const [ioc, setIoc] = useState("");
  const [data, setData] = useState(null);
  const [activeTab, setActiveTab] = useState("overview");
  const [loading, setLoading] = useState(false);
  const [drawer, setDrawer] = useState(null);

  const analyze = async () => {
    if (!ioc.trim()) return alert("Enter IOC first");
    setLoading(true);
    setData(null);

    try {
      const res = await axios.post(`${API}/api/threat-intel`, { ioc });
      setData(res.data);
    } catch {
      alert("Backend not connected or API failed");
    }

    setLoading(false);
  };

  const t = data?.threat_data || {};
  const risk = data?.risk || {};
  const vt = t.virustotal || {};
  const abuse = t.abuseipdb || {};
  const geo = t.geoip || {};
  const nmap = t.nmap || {};
  const cves = t.cves || [];
  const mitre = t.mitre_attack || [];
  const summary = data?.soc_summary || {};
  const verdict = data?.executive_verdict || {};
  const story = data?.ioc_story || {};
  const attack = data?.attack_surface || [];
  const classification = data?.threat_classification || {};
  const confidence = data?.confidence_breakdown || {};
  const cveSummary = data?.cve_summary || {};

  const vtChart = [
    { name: "Malicious", value: vt.malicious || 0 },
    { name: "Suspicious", value: vt.suspicious || 0 },
    { name: "Harmless", value: vt.harmless || 0 },
    { name: "Undetected", value: vt.undetected || 0 },
  ];

  const confidenceChart = Object.entries(confidence.breakdown || {}).map(([key, value]) => ({
    name: key.replace("_", " "),
    value,
  }));

  const cveChart = [
    { name: "Critical", value: cveSummary.critical || 0 },
    { name: "High", value: cveSummary.high || 0 },
    { name: "Medium", value: cveSummary.medium || 0 },
    { name: "Low", value: cveSummary.low || 0 },
  ];

  const mitreCounts = {};
  mitre.forEach((m) => {
    mitreCounts[m.tactic] = (mitreCounts[m.tactic] || 0) + 1;
  });

  const mitreChart = Object.entries(mitreCounts).map(([name, value]) => ({
    name,
    value,
  }));

  return (
    <div className="soc-layout">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">AI</div>
          <div>
            <h2>Security Copilot</h2>
            <p>SOC Platform</p>
          </div>
        </div>

        {["overview", "intel", "network", "cves", "mitre", "summary", "playbooks"].map((tab) => (
          <button
            key={tab}
            className={activeTab === tab ? "nav-active" : ""}
            onClick={() => setActiveTab(tab)}
          >
            {tab.toUpperCase()}
          </button>
        ))}
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <h1>AI Security Copilot</h1>
            <p>Intelligent Threat Intelligence & SOC Dashboard</p>
          </div>
          <span className="live">LIVE</span>
        </header>

        <section className="search-box">
          <input
            value={ioc}
            onChange={(e) => setIoc(e.target.value)}
            placeholder="Enter IP, Domain, URL, MD5, SHA1 or SHA256"
          />
          <button onClick={analyze}>{loading ? "Analyzing..." : "Analyze IOC"}</button>
        </section>

        {!data && <div className="empty">Enter IOC to start investigation.</div>}

        {data && (
          <>
            <section className="hero-grid">
              <div className={`risk-card ${risk.severity?.toLowerCase()}`}>
                <h3>Risk Score</h3>
                <div className="risk-score">{risk.score}/100</div>
                <h2>{risk.severity}</h2>
                <p>{summary.analyst_verdict}</p>
                <ul>{risk.reasons?.map((r, i) => <li key={i}>{r}</li>)}</ul>
              </div>

              <div className="panel">
                <h2>Executive Verdict</h2>
                <p>{verdict.executive_summary}</p>
                <div className="badges">
                  <span>{verdict.recommended_priority}</span>
                  <span>{verdict.business_impact} Business Impact</span>
                  <span>{verdict.technical_impact} Technical Impact</span>
                </div>
              </div>
            </section>

            {activeTab === "overview" && (
              <>
                <div className="cards-grid">
                  <Metric title="IOC" value={data.ioc} sub={data.ioc_type} />
                  <Metric title="VirusTotal" value={vt.detection_rate || "N/A"} sub={`${vt.malicious || 0} malicious`} />
                  <Metric title="AbuseIPDB" value={abuse.abuse_confidence_score ?? "N/A"} sub={`${abuse.total_reports || 0} reports`} />
                  <Metric title="Location" value={geo.country || "N/A"} sub={geo.isp} />
                  <Metric title="CVEs" value={cveSummary.total || 0} sub={`${cveSummary.high || 0} high`} />
                  <Metric title="Confidence" value={`${confidence.overall_confidence || 0}%`} sub="Threat confidence" />
                </div>

                <div className="chart-grid">
                  <ChartPanel title="VirusTotal Stats">
                    <ResponsiveContainer width="100%" height={240}>
                      <PieChart>
                        <Pie data={vtChart} dataKey="value" nameKey="name" outerRadius={90} label>
                          {vtChart.map((_, i) => <Cell key={i} fill={COLORS[i]} />)}
                        </Pie>
                        <Tooltip />
                      </PieChart>
                    </ResponsiveContainer>
                  </ChartPanel>

                  <ChartPanel title="Confidence Breakdown">
                    <ResponsiveContainer width="100%" height={240}>
                      <BarChart data={confidenceChart}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="name" />
                        <YAxis />
                        <Tooltip />
                        <Bar dataKey="value" fill="#2563eb" />
                      </BarChart>
                    </ResponsiveContainer>
                  </ChartPanel>
                </div>

                <Panel title="IOC Story">
                  <p>{story.executive_summary}</p>
                </Panel>

                <Panel title="Threat Classification">
                  <div className="badges">
                    {classification.categories?.map((x, i) => <span key={i}>{x}</span>)}
                  </div>
                  <p><b>Confidence:</b> {classification.confidence}</p>
                  <p><b>Label:</b> {classification.final_label}</p>
                </Panel>
              </>
            )}

            {activeTab === "intel" && (
              <>
                <Panel title="VirusTotal Detection Details">
                  <div className="cards-grid">
                    <Metric title="Malicious" value={vt.malicious} />
                    <Metric title="Suspicious" value={vt.suspicious} />
                    <Metric title="Harmless" value={vt.harmless} />
                    <Metric title="Undetected" value={vt.undetected} />
                  </div>

                  <Table
                    headers={["Engine", "Category", "Result"]}
                    rows={(vt.malicious_engines || []).map((e) => [e.engine, e.category, e.result])}
                  />
                </Panel>

                <Panel title="AbuseIPDB">
                  <div className="cards-grid">
                    <Metric title="Score" value={abuse.abuse_confidence_score} />
                    <Metric title="Reports" value={abuse.total_reports} />
                    <Metric title="ISP" value={abuse.isp} />
                    <Metric title="Usage" value={abuse.usage_type} />
                  </div>
                </Panel>

                <Panel title="GeoIP">
                  <Table
                    headers={["Field", "Value"]}
                    rows={[
                      ["Country", geo.country],
                      ["Region", geo.region],
                      ["City", geo.city],
                      ["ISP", geo.isp],
                      ["Organization", geo.org],
                      ["ASN", geo.as],
                    ]}
                  />
                </Panel>
              </>
            )}

            {activeTab === "network" && (
              <>
                <Panel title="Open Ports - Click Any Port">
                  <div className="click-grid">
                    {(nmap.open_ports || []).map((p, i) => (
                      <div className="click-card" key={i} onClick={() => setDrawer({ type: "port", data: p })}>
                        <div className="click-title">Port {p.port}</div>
                        <div>{p.service}</div>
                        <small>{p.product || "N/A"} {p.version || ""}</small>
                        <span className="mini-badge">{p.state}</span>
                      </div>
                    ))}
                  </div>
                </Panel>

                <Panel title="Attack Surface">
                  {attack.map((a, i) => (
                    <div className="attack-card" key={i}>
                      <h4>{a.port}/{a.service} — {a.product} {a.version}</h4>
                      <p><b>Risks:</b> {a.risks?.join(", ")}</p>
                      <p><b>Recommendations:</b> {a.recommendations?.join(", ")}</p>
                    </div>
                  ))}
                </Panel>
              </>
            )}

            {activeTab === "cves" && (
              <>
                <div className="chart-grid">
                  <ChartPanel title="CVE Severity Distribution">
                    <ResponsiveContainer width="100%" height={240}>
                      <PieChart>
                        <Pie data={cveChart} dataKey="value" nameKey="name" outerRadius={90} label>
                          {cveChart.map((_, i) => <Cell key={i} fill={COLORS[i]} />)}
                        </Pie>
                        <Tooltip />
                      </PieChart>
                    </ResponsiveContainer>
                  </ChartPanel>
                </div>

                <Panel title="CVE Intelligence - Click CVE for Details">
                  <div className="cards-grid">
                    <Metric title="Total" value={cveSummary.total} />
                    <Metric title="Critical" value={cveSummary.critical} />
                    <Metric title="High" value={cveSummary.high} />
                    <Metric title="Medium" value={cveSummary.medium} />
                  </div>

                  {cves.map((item, i) => (
                    <div className="cve-service" key={i}>
                      <h4>{item.product} {item.version} — Port {item.port}</h4>
                      <p>{item.version_status?.message}: {item.version_status?.recommendation}</p>

                      <div className="click-grid">
                        {(item.cves || []).length === 0 ? (
                          <div className="click-card">No CVEs found for this service.</div>
                        ) : (
                          item.cves.map((cve, j) => (
                            <div
                              className="click-card danger"
                              key={j}
                              onClick={() =>
                                setDrawer({
                                  type: "cve",
                                  data: { ...cve, product: item.product, version: item.version, patch: item.patch_advisory },
                                })
                              }
                            >
                              <div className="click-title">{cve.cve_id}</div>
                              <div>{cve.severity} | CVSS {cve.cvss_score}</div>
                              <small>{item.product} {item.version}</small>
                            </div>
                          ))
                        )}
                      </div>
                    </div>
                  ))}
                </Panel>
              </>
            )}

            {activeTab === "mitre" && (
              <>
                <div className="chart-grid">
                  <ChartPanel title="MITRE Tactic Distribution">
                    <ResponsiveContainer width="100%" height={260}>
                      <BarChart data={mitreChart}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="name" />
                        <YAxis />
                        <Tooltip />
                        <Bar dataKey="value" fill="#f59e0b" />
                      </BarChart>
                    </ResponsiveContainer>
                  </ChartPanel>
                </div>

                <Panel title="MITRE ATT&CK Mapping - Click Technique">
                  <div className="mitre-grid">
                    {mitre.map((m, i) => (
                      <div className="mitre-card" key={i} onClick={() => setDrawer({ type: "mitre", data: m })}>
                        <b>{m.technique_id}</b>
                        <h4>{m.technique_name}</h4>
                        <p>{m.tactic}</p>
                        <small>{m.reason}</small>
                      </div>
                    ))}
                  </div>
                </Panel>
              </>
            )}

            {activeTab === "summary" && (
              <>
                <Panel title="SOC Summary">
                  <p>{summary.summary}</p>
                  <h4>Priority: {summary.priority}</h4>
                  <h4>Key Observations</h4>
                  <ul>{summary.key_observations?.map((x, i) => <li key={i}>{x}</li>)}</ul>
                  <h4>Recommended Actions</h4>
                  <ul>{summary.recommended_actions?.map((x, i) => <li key={i}>{x}</li>)}</ul>
                </Panel>

                <Panel title="PDF Report">
                  <p><b>File:</b> {data.pdf_report?.filename}</p>
                  <p><b>Path:</b> {data.pdf_report?.path}</p>
                </Panel>
              </>
            )}

            {activeTab === "playbooks" && (
              <Panel title="Action Playbooks - Click Any Playbook">
                {summary.playbooks?.map((pb, i) => (
                  <details className="playbook" key={i}>
                    <summary onClick={() => setDrawer({ type: "playbook", data: pb })}>{pb.issue}</summary>
                    <p>{pb.risk}</p>
                    <h4>Recommended Actions</h4>
                    <ul>{pb.recommended_actions?.map((a, j) => <li key={j}>{a}</li>)}</ul>
                    <h4>Linux Commands</h4>
                    {pb.linux_commands?.map((cmd, j) => <code key={j}>{cmd}</code>)}
                  </details>
                ))}
              </Panel>
            )}
          </>
        )}

        {drawer && (
          <div className="drawer-backdrop" onClick={() => setDrawer(null)}>
            <aside className="drawer" onClick={(e) => e.stopPropagation()}>
              <button className="drawer-close" onClick={() => setDrawer(null)}>×</button>

              {drawer.type === "port" && (
                <>
                  <h2>Port {drawer.data.port} Details</h2>
                  <p><b>Service:</b> {drawer.data.service}</p>
                  <p><b>Product:</b> {drawer.data.product || "N/A"}</p>
                  <p><b>Version:</b> {drawer.data.version || "N/A"}</p>
                  <p><b>State:</b> {drawer.data.state}</p>
                  <p><b>Extra Info:</b> {drawer.data.extrainfo || "N/A"}</p>
                  <p><b>CPE:</b> {(drawer.data.cpe || []).join(", ") || "N/A"}</p>
                </>
              )}

              {drawer.type === "cve" && (
                <>
                  <h2>{drawer.data.cve_id}</h2>
                  <p><b>Product:</b> {drawer.data.product} {drawer.data.version}</p>
                  <p><b>Severity:</b> {drawer.data.severity}</p>
                  <p><b>CVSS:</b> {drawer.data.cvss_score}</p>
                  <p><b>Vector:</b> {drawer.data.cvss_vector || "N/A"}</p>
                  <p><b>Published:</b> {drawer.data.published}</p>
                  <h3>Description</h3>
                  <p>{drawer.data.description}</p>
                  <h3>Patch Recommendation</h3>
                  <p>{drawer.data.patch?.recommendation}</p>
                  {(drawer.data.patch?.linux_commands || []).map((cmd, i) => <code key={i}>{cmd}</code>)}
                </>
              )}

              {drawer.type === "mitre" && (
                <>
                  <h2>{drawer.data.technique_id}</h2>
                  <p><b>Technique:</b> {drawer.data.technique_name}</p>
                  <p><b>Tactic:</b> {drawer.data.tactic}</p>
                  <h3>Reason</h3>
                  <p>{drawer.data.reason}</p>
                </>
              )}

              {drawer.type === "playbook" && (
                <>
                  <h2>{drawer.data.issue}</h2>
                  <p>{drawer.data.risk}</p>
                  <h3>Recommended Actions</h3>
                  <ul>{drawer.data.recommended_actions?.map((a, i) => <li key={i}>{a}</li>)}</ul>
                  <h3>Linux Commands</h3>
                  {drawer.data.linux_commands?.map((cmd, i) => <code key={i}>{cmd}</code>)}
                </>
              )}
            </aside>
          </div>
        )}
      </main>
    </div>
  );
}

function Metric({ title, value, sub }) {
  return (
    <div className="metric">
      <p>{title}</p>
      <h3>{value ?? "N/A"}</h3>
      {sub && <span>{sub}</span>}
    </div>
  );
}

function Panel({ title, children }) {
  return (
    <section className="panel">
      <h2>{title}</h2>
      {children}
    </section>
  );
}

function ChartPanel({ title, children }) {
  return (
    <section className="panel">
      <h2>{title}</h2>
      {children}
    </section>
  );
}

function Table({ headers, rows }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>{headers.map((h, i) => <th key={i}>{h}</th>)}</tr>
        </thead>
        <tbody>
          {(rows || []).length === 0 ? (
            <tr><td colSpan={headers.length}>No data available</td></tr>
          ) : (
            rows.map((row, i) => (
              <tr key={i}>{row.map((cell, j) => <td key={j}>{cell || "N/A"}</td>)}</tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

export default Dashboard;
