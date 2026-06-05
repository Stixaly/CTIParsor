import { Routes, Route, Navigate } from 'react-router-dom'
import { ThemeProvider } from './context/ThemeContext'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Review from './pages/Review'
import Graph from './pages/Graph'
import Policy from './pages/Policy'

export default function App() {
  return (
    <ThemeProvider>
      <Routes>
        {/* ── Sidebar layout — Dashboard + Policy ── */}
        <Route element={<Layout />}>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/policy"    element={<Policy />} />
        </Route>

        {/* ── Full-screen — Review + Graph (no sidebar) ── */}
        <Route path="/review/:jobId" element={<Review />} />
        <Route path="/graph/:jobId"  element={<Graph />} />
      </Routes>
    </ThemeProvider>
  )
}
