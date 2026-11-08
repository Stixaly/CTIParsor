import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { KeyRound, LayoutDashboard, Link2, LogOut, Settings as SettingsIcon, Tag, Users } from 'lucide-react'
import ThemeSwitcher from './ThemeSwitcher'
import { useAuth } from '../context/AuthContext'

/** Sidebar shell used by Dashboard and Policy.
 *  Review and Graph are full-screen and rendered outside this layout. */
export default function Layout() {
  const auth = useAuth()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const admin = auth.can('admin')
  const signedIn = auth.status === 'signed-in'
  const signOut = async () => {
    await auth.signOut()
    queryClient.clear()
    navigate('/login', { replace: true })
  }
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
            { to: '/dashboard', icon: <LayoutDashboard size={15} />, label: 'Dashboard', show: true },
            { to: '/policy',    icon: <Link2 size={15} />,           label: 'Policy',    show: admin },
            { to: '/settings',  icon: <SettingsIcon size={15} />,    label: 'Settings',  show: admin },
            { to: '/access',    icon: <Users size={15} />,           label: 'Access',    show: admin && signedIn },
            { to: '/account',   icon: <KeyRound size={15} />,        label: 'My tokens', show: signedIn },
          ].filter(item => item.show).map(({ to, icon, label }) => (
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

        {/* Who is signed in — absent with authentication off */}
        {auth.status === 'signed-in' && auth.me && (
          <div style={{ borderTop: '1px solid var(--rule)', padding: '10px 12px', fontSize: 12.5 }}>
            <div style={{ color: 'var(--ink)', fontWeight: 600, overflowWrap: 'anywhere' }}>
              {auth.me.display_name || auth.me.username}
            </div>
            <div style={{ color: 'var(--ink-3)', marginBottom: 8 }}>{auth.me.role}</div>
            <button type="button" className="btn-ghost" onClick={() => void signOut()}>
              <LogOut size={13} />
              Sign out
            </button>
          </div>
        )}

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
          {/* lucide-react 1.x has no brand icons; this was a GitHub mark, not a link */}
          <Tag size={11} />
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
