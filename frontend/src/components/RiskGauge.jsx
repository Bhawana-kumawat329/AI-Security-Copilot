function RiskGauge({ risk }) {
  return (
    <div className="card risk-card">
      <h3>Risk Score</h3>
      <div className="score">{risk?.score ?? 0}/100</div>
      <h2>{risk?.severity ?? "Unknown"}</h2>
      <ul>
        {(risk?.reasons || []).map((r, i) => <li key={i}>{r}</li>)}
      </ul>
    </div>
  );
}
export default RiskGauge;
