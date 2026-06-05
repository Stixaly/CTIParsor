import { NavLink, Outlet } from 'react-router-dom'
import { LayoutDashboard, Github, Link2 } from 'lucide-react'
import ThemeSwitcher from './ThemeSwitcher'

/** Sidebar shell used by Dashboard and Policy.
 *  Review and Graph are full-screen and rendered outside this layout. */
export default function Layout() {
  return (
    <div className="t-app" style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>

      {/* ── Sidebar ─────────────────────────────────────────────────────── */}
      <aside className="t-sidebar" style={{ width: 210, flexShrink: 0, display: 'flex', flexDirection: 'column' }}>

        {/* Logo */}
        <div className="t-topbar" style={{ display: 'flex', alignItems: 'center', padding: '10px 12px', borderBottom: '1px solid var(--rule)', background: 'var(--bg-elev)' }}>
          {/* Logo — raven + CTIParsor wordmark from the actual brand image */}
          <img
            src="/logo.png"
            alt="CTIParsor"
            style={{
              width: 164,
              height: 'auto',
              objectFit: 'contain',
              filter: 'var(--logo-filter, none)',
            }}
          />
        </div>

        {/* Nav */}
        <nav style={{ flex: 1, padding: '12px 8px' }}>
          {[
            { to: '/dashboard', icon: <LayoutDashboard size={15} />, label: 'Dashboard' },
            { to: '/policy',    icon: <Link2 size={15} />,           label: 'Policy'    },
          ].map(({ to, icon, label }) => (
            <NavLink
              key={to}
              to={to}
              style={({ isActive }) => ({
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '8px 10px',
                borderRadius: 7,
                fontSize: 13,
                fontWeight: 500,
                textDecoration: 'none',
                transition: 'background .15s, color .15s',
                background: isActive ? 'var(--accent-soft)' : 'transparent',
                color: isActive ? 'var(--accent)' : 'var(--ink-3)',
              })}
            >
              {icon}
              {label}
            </NavLink>
          ))}
        </nav>

        {/* Theme switcher */}
        <div style={{ borderTop: '1px solid var(--rule)', padding: '12px 12px 8px' }}>
          <ThemeSwitcher />
        </div>

        {/* Footer */}
        <div style={{
          padding: '10px 14px',
          borderTop: '1px solid var(--rule-soft)',
          fontSize: 11,
          color: 'var(--ink-4)',
          display: 'flex',
          alignItems: 'center',
          gap: 5,
        }}>
          <Github size={11} />
          cti-to-stix v1.0
        </div>
      </aside>

      {/* ── Main content ────────────────────────────────────────────────── */}
      <main style={{ flex: 1, overflow: 'auto', background: 'var(--bg)', color: 'var(--ink)' }}>
        <Outlet />
      </main>
    </div>
  )
}
