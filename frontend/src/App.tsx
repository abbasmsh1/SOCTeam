import { Routes, Route } from 'react-router-dom'
import Dashboard from './components/Dashboard'
import AgentReportPage from './components/AgentReportPage'

function App() {
  return (
    <div className="max-w-[1600px] mx-auto pb-20">
      <Routes>
        <Route path="/" element={
          <>
            <Dashboard />
            <div className="px-6 space-y-6">
              <div id="live-monitor" />
              {/* Other components will be added here or integrated into Dashboard */}
            </div>
          </>
        } />
        <Route path="/report/:reportId" element={<AgentReportPage />} />
      </Routes>
    </div>
  )
}

export default App
