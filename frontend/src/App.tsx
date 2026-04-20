import { Routes, Route, Navigate } from 'react-router-dom'
import Dashboard from './components/Dashboard'
import AgentReportPage from './components/AgentReportPage'
import QuarantinePage from './components/QuarantinePage'

function App() {
  return (
    <div className="max-w-[1600px] mx-auto pb-20">
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/report/:reportId" element={<AgentReportPage />} />
        <Route path="/quarantine" element={<QuarantinePage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </div>
  )
}

export default App
