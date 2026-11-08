import { Routes, Route, Navigate, useParams } from 'react-router-dom'
import { ThemeProvider } from './context/ThemeContext'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Review from './pages/Review'
import Graph from './pages/Graph'
import Coverage from './pages/Coverage'
import Policy from './pages/Policy'
import Settings from './pages/Settings'
import Login from './pages/Login'
import { AuthProvider } from './context/AuthContext'
import { RequireAuth, RequireRole } from './components/RequireAuth'

// Keyed by job: another job remounts the review, so nothing from the last one
// (bootstrap refs, "review completed", "bundle outdated") carries over (#450).
// Preferences live in localStorage and survive the remount.
function ReviewForJob() {
  const { jobId } = useParams<{ jobId: string }>()
  return <Review key={jobId} />
}

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <Routes>
          {/* ── Sign-in — outside the layout, and open ── */}
          <Route path="/login" element={<Login />} />

          <Route element={<RequireAuth />}>
            {/* ── Sidebar layout — Dashboard + Policy ── */}
            <Route element={<Layout />}>
              <Route path="/" element={<Navigate to="/dashboard" replace />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route element={<RequireRole role="admin" />}>
                <Route path="/policy"    element={<Policy />} />
                <Route path="/settings"  element={<Settings />} />
              </Route>
            </Route>

            {/* ── Full-screen — Review + Graph (no sidebar) ── */}
            <Route path="/review/:jobId" element={<ReviewForJob />} />
            <Route path="/graph/:jobId"  element={<Graph />} />
            <Route path="/coverage/:jobId" element={<Coverage />} />
          </Route>
        </Routes>
      </AuthProvider>
    </ThemeProvider>
  )
}
