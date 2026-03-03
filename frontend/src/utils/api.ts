import axios from "axios";

const API_KEY = "ids-secret-key"; // matches backend default
const BASE_URL = "http://localhost:6050";

const api = axios.create({
  baseURL: BASE_URL,
  headers: {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json",
  },
});

export const idsApi = {
  predict: (data: any) => api.post("/predict/", data),
  processWorkflow: (alertData: any) => api.post("/workflow/process", alertData),
  getReports: () => api.get("/reports"),
  getReportById: (id: string) => api.get(`/reports/${id}`),
  getEvents: () => api.get("/events"),
  getStats: () => api.get("/events/stats"),
  getRemediationLogs: () => api.get("/remediation/logs"),
};

export default api;
