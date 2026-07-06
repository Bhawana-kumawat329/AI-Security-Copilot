import axios from "axios";

const API_BASE_URL = "http://127.0.0.1:8000";

export async function analyzeIOC(ioc) {
  const res = await axios.post(`${API_BASE_URL}/api/threat-intel`, { ioc });
  return res.data;
}

export async function getHistory() {
  const res = await axios.get(`${API_BASE_URL}/api/history/`);
  return res.data;
}
