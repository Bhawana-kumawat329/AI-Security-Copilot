function SocSummary({ summary }) {
  if (!summary) return null;

  return (
    <div className="card summary-card">
      <h3>SOC Summary</h3>
      <p>{summary.summary}</p>
      <h4>Priority: {summary.priority}</h4>

      <h4>Key Observations</h4>
      <ul>{summary.key_observations?.map((x, i) => <li key={i}>{x}</li>)}</ul>

      <h4>Recommended Actions</h4>
      <ul>{summary.recommended_actions?.map((x, i) => <li key={i}>{x}</li>)}</ul>
    </div>
  );
}
export default SocSummary;
