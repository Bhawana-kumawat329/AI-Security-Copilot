import { useState } from "react";

function SearchBar({ onAnalyze, loading }) {
  const [ioc, setIoc] = useState("");

  const submit = () => {
    if (!ioc.trim()) return alert("Enter IOC first");
    onAnalyze(ioc);
  };

  return (
    <div className="search-card">
      <input
        value={ioc}
        onChange={(e) => setIoc(e.target.value)}
        placeholder="Enter IP, domain, URL, email or hash"
      />
      <button onClick={submit}>{loading ? "Analyzing..." : "Analyze"}</button>
    </div>
  );
}
export default SearchBar;
