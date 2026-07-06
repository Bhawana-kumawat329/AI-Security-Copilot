function InfoCards({ data }) {
  const t = data?.threat_data || {};
  return (
    <div className="info-grid">
      <div className="card"><h3>IOC</h3><p>{data?.ioc}</p><span>{data?.ioc_type}</span></div>
      <div className="card"><h3>VirusTotal</h3><p>{t.virustotal?.malicious ?? "N/A"} malicious</p></div>
      <div className="card"><h3>AbuseIPDB</h3><p>{t.abuseipdb?.abuse_confidence_score ?? "N/A"} score</p></div>
      <div className="card"><h3>GeoIP</h3><p>{t.geoip?.country ?? "N/A"}</p><span>{t.geoip?.isp ?? ""}</span></div>
    </div>
  );
}
export default InfoCards;
