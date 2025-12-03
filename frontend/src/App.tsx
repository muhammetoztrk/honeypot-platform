import { useEffect, useMemo, useState } from 'react'
import {
  NavLink,
  Navigate,
  Outlet,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from 'react-router-dom'
import axios from 'axios'
import SetupWizard from './SetupWizard'
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'

const apiBase =
  (import.meta as any).env?.VITE_API_URL ||
  (typeof window !== 'undefined' ? (window as any).VITE_API_URL : undefined) ||
  'http://localhost:8000'

export const api = axios.create({
  baseURL: apiBase,
})

function useAuthToken() {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem('token'))

  const update = (next: string | null) => {
    if (next) {
      localStorage.setItem('token', next)
      api.defaults.headers.common.Authorization = `Bearer ${next}`
    } else {
      localStorage.removeItem('token')
      delete api.defaults.headers.common.Authorization
    }
    setToken(next)
  }

  return { token, setToken: update }
}

function RequireAuth() {
  const { token } = useAuthToken()
  const location = useLocation()

  if (!token) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  return <Outlet />
}

function LayoutShell() {
  const location = useLocation()
  const navigate = useNavigate()
  const [email] = useState('admin@example.com')
  const [alertCount, setAlertCount] = useState(0)
  const [theme, setThemeState] = useState<'dark' | 'light'>(() => {
    const saved = localStorage.getItem('honeypot_theme') as 'dark' | 'light'
    return saved || 'dark'
  })

  useEffect(() => {
    localStorage.setItem('honeypot_theme', theme)
    document.documentElement.setAttribute('data-theme', theme)
  }, [theme])

  const toggleTheme = () => {
    setThemeState(prev => prev === 'dark' ? 'light' : 'dark')
  }

  const activeKey = useMemo(() => {
    if (location.pathname.startsWith('/nodes')) return 'nodes'
    if (location.pathname.startsWith('/honeypots')) return 'honeypots'
    if (location.pathname.startsWith('/events')) return 'events'
    if (location.pathname.startsWith('/iocs')) return 'iocs'
    if (location.pathname.startsWith('/threat-map')) return 'threat-map'
    if (location.pathname.startsWith('/alert-rules')) return 'alert-rules'
    if (location.pathname.startsWith('/blocked-ips')) return 'blocked-ips'
    if (location.pathname.startsWith('/webhooks')) return 'webhooks'
    if (location.pathname.startsWith('/reports')) return 'reports'
    if (location.pathname.startsWith('/analytics')) return 'analytics'
    if (location.pathname.startsWith('/incidents')) return 'incidents'
    if (location.pathname.startsWith('/mitre')) return 'mitre'
    if (location.pathname.startsWith('/playbooks')) return 'playbooks'
    if (location.pathname.startsWith('/campaigns')) return 'campaigns'
    if (location.pathname.startsWith('/attack-replay')) return 'attack-replay'
    if (location.pathname.startsWith('/detection-lab')) return 'detection-lab'
    if (location.pathname.startsWith('/ml-anomaly')) return 'ml-anomaly'
    if (location.pathname.startsWith('/threat-intel')) return 'threat-intel'
    if (location.pathname.startsWith('/honeypot-health')) return 'honeypot-health'
    if (location.pathname.startsWith('/geo-blocking')) return 'geo-blocking'
    if (location.pathname.startsWith('/siem-integration')) return 'siem-integration'
    if (location.pathname.startsWith('/compliance')) return 'compliance'
    if (location.pathname.startsWith('/analytics')) return 'analytics'
    if (location.pathname.startsWith('/threat-actors')) return 'threat-actors'
    if (location.pathname.startsWith('/yara-rules')) return 'yara-rules'
    if (location.pathname.startsWith('/rate-limiting')) return 'rate-limiting'
    if (location.pathname.startsWith('/honeytokens')) return 'honeytokens'
    if (location.pathname.startsWith('/webhooks')) return 'webhooks'
    if (location.pathname.startsWith('/audit-logs')) return 'audit-logs'
    if (location.pathname.startsWith('/tags')) return 'tags'
    if (location.pathname.startsWith('/suppress-rules')) return 'suppress-rules'
    if (location.pathname.startsWith('/logs')) return 'logs'
    if (location.pathname.startsWith('/users')) return 'users'
    if (location.pathname.startsWith('/templates')) return 'templates'
    if (location.pathname.startsWith('/backups')) return 'backups'
    if (location.pathname.startsWith('/settings')) return 'settings'
    return 'dashboard'
  }, [location.pathname])

  useEffect(() => {
    const loadAlerts = () => {
      const token = localStorage.getItem('token')
      if (token) {
        api.defaults.headers.common.Authorization = `Bearer ${token}`
        api
          .get('/api/v1/alerts?unread_only=true&limit=100')
          .then(res => setAlertCount(Array.isArray(res.data) ? res.data.length : 0))
          .catch(() => setAlertCount(0))
      }
    }
    loadAlerts()
    const interval = setInterval(loadAlerts, 10000)
    return () => clearInterval(interval)
  }, [])

  const handleLogout = () => {
    localStorage.removeItem('token')
    delete api.defaults.headers.common.Authorization
    navigate('/login')
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-logo">
          <div className="sidebar-logo-icon">H</div>
          <div className="sidebar-logo-text">
            <span className="sidebar-logo-title">Honeypot</span>
            <span className="sidebar-logo-subtitle">Deception platform</span>
          </div>
        </div>

        <div>
          <div className="sidebar-section-label">Overview</div>
          <nav className="sidebar-nav">
            <NavLink
              to="/"
              end
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'dashboard' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">📊</span>
              <span className="sidebar-link-label">Dashboard</span>
            </NavLink>
            <NavLink
              to="/nodes"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'nodes' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">🖥️</span>
              <span className="sidebar-link-label">Nodes</span>
              <span className="sidebar-link-pill">Agents</span>
            </NavLink>
            <NavLink
              to="/honeypots"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'honeypots' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">🎯</span>
              <span className="sidebar-link-label">Honeypots</span>
            </NavLink>
          </nav>

          <div className="sidebar-section-label" style={{ marginTop: 18 }}>
            Intelligence
          </div>
          <nav className="sidebar-nav">
            <NavLink
              to="/events"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'events' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">📡</span>
              <span className="sidebar-link-label">Events</span>
              {alertCount > 0 && (
                <span
                  className="sidebar-link-pill"
                  style={{
                    background: 'rgba(239, 68, 68, 0.2)',
                    color: '#fca5a5',
                    border: '1px solid rgba(239, 68, 68, 0.5)',
                  }}
                >
                  {alertCount}
                </span>
              )}
            </NavLink>
            <NavLink
              to="/iocs"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'iocs' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">🧬</span>
              <span className="sidebar-link-label">IOCs</span>
            </NavLink>
            <NavLink
              to="/threat-map"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'threat-map' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">🗺️</span>
              <span className="sidebar-link-label">Threat Map</span>
            </NavLink>
          </nav>

          <div className="sidebar-section-label" style={{ marginTop: 18 }}>
            Security
          </div>
          <nav className="sidebar-nav">
            <NavLink
              to="/alert-rules"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'alert-rules' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">⚡</span>
              <span className="sidebar-link-label">Alert Rules</span>
            </NavLink>
            <NavLink
              to="/blocked-ips"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'blocked-ips' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">🚫</span>
              <span className="sidebar-link-label">Blocked IPs</span>
            </NavLink>
            <NavLink
              to="/webhooks"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'webhooks' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">🔗</span>
              <span className="sidebar-link-label">Webhooks</span>
            </NavLink>
            <NavLink
              to="/reports"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'reports' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">📄</span>
              <span className="sidebar-link-label">Reports</span>
            </NavLink>
            <NavLink
              to="/analytics"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'analytics' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">📊</span>
              <span className="sidebar-link-label">Analytics</span>
            </NavLink>
            <NavLink
              to="/incidents"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'incidents' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">🚨</span>
              <span className="sidebar-link-label">Incidents</span>
            </NavLink>
            <NavLink
              to="/mitre"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'mitre' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">🎯</span>
              <span className="sidebar-link-label">MITRE ATT&CK</span>
            </NavLink>
            <NavLink
              to="/playbooks"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'playbooks' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">📖</span>
              <span className="sidebar-link-label">Playbooks</span>
            </NavLink>
            <NavLink
              to="/campaigns"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'campaigns' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">🎯</span>
              <span className="sidebar-link-label">Campaigns</span>
            </NavLink>
            <NavLink
              to="/attack-replay"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'attack-replay' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">▶️</span>
              <span className="sidebar-link-label">Attack Replay</span>
            </NavLink>
            <NavLink
              to="/detection-lab"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'detection-lab' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">🔬</span>
              <span className="sidebar-link-label">Detection Lab</span>
            </NavLink>
            <NavLink
              to="/ml-anomaly"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'ml-anomaly' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">🤖</span>
              <span className="sidebar-link-label">ML Anomaly</span>
            </NavLink>
            <NavLink
              to="/threat-intel"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'threat-intel' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">🔍</span>
              <span className="sidebar-link-label">Threat Intel</span>
            </NavLink>
            <NavLink
              to="/honeypot-health"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'honeypot-health' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">💚</span>
              <span className="sidebar-link-label">Honeypot Health</span>
            </NavLink>
            <NavLink
              to="/geo-blocking"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'geo-blocking' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">🌍</span>
              <span className="sidebar-link-label">Geo-Blocking</span>
            </NavLink>
            <NavLink
              to="/siem-integration"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'siem-integration' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">🔗</span>
              <span className="sidebar-link-label">SIEM Integration</span>
            </NavLink>
            <NavLink
              to="/compliance"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'compliance' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">📋</span>
              <span className="sidebar-link-label">Compliance</span>
            </NavLink>
            <NavLink
              to="/analytics"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'analytics' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">📊</span>
              <span className="sidebar-link-label">Advanced Analytics</span>
            </NavLink>
            <NavLink
              to="/threat-actors"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'threat-actors' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">🎭</span>
              <span className="sidebar-link-label">Threat Actors</span>
            </NavLink>
            <NavLink
              to="/yara-rules"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'yara-rules' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">🔐</span>
              <span className="sidebar-link-label">YARA Rules</span>
            </NavLink>
            <NavLink
              to="/rate-limiting"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'rate-limiting' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">⏱️</span>
              <span className="sidebar-link-label">Rate Limiting</span>
            </NavLink>
            <NavLink
              to="/honeytokens"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'honeytokens' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">🍯</span>
              <span className="sidebar-link-label">Honeytokens</span>
            </NavLink>
            <NavLink
              to="/webhooks"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'webhooks' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">🔔</span>
              <span className="sidebar-link-label">Webhooks</span>
            </NavLink>
            <NavLink
              to="/audit-logs"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'audit-logs' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">📝</span>
              <span className="sidebar-link-label">Audit Logs</span>
            </NavLink>
            <NavLink
              to="/tags"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'tags' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">🏷️</span>
              <span className="sidebar-link-label">Tags</span>
            </NavLink>
            <NavLink
              to="/logs"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'logs' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">📋</span>
              <span className="sidebar-link-label">Logs</span>
            </NavLink>
          </nav>

          <div className="sidebar-section-label" style={{ marginTop: 18 }}>
            Administration
          </div>
          <nav className="sidebar-nav">
            <NavLink
              to="/users"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'users' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">👥</span>
              <span className="sidebar-link-label">Users</span>
            </NavLink>
            <NavLink
              to="/templates"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'templates' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">📝</span>
              <span className="sidebar-link-label">Templates</span>
            </NavLink>
            <NavLink
              to="/backups"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'backups' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">💾</span>
              <span className="sidebar-link-label">Backups</span>
            </NavLink>
            <NavLink
              to="/settings"
              className={({ isActive }) => `sidebar-link ${isActive || activeKey === 'settings' ? 'active' : ''}`}
            >
              <span className="sidebar-link-icon">⚙️</span>
              <span className="sidebar-link-label">Settings</span>
            </NavLink>
          </nav>
        </div>

        <div className="sidebar-footer">
          <div className="sidebar-user">
            <div className="sidebar-user-avatar">{email[0]?.toUpperCase()}</div>
            <div className="sidebar-user-meta">
              <span className="sidebar-user-name">{email}</span>
              <span className="sidebar-user-role">Admin</span>
            </div>
          </div>
          <button className="sidebar-logout-btn" type="button" onClick={handleLogout}>
            Log out
          </button>
        </div>
      </aside>

      <div className="main-area">
        <header className="topbar">
          <div className="topbar-title">Honeypot Deception Platform</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <button
              onClick={toggleTheme}
              style={{
                padding: '6px 12px',
                borderRadius: 6,
                border: '1px solid #4b5563',
                background: 'rgba(15, 23, 42, 0.5)',
                color: '#e5e7eb',
                cursor: 'pointer',
                fontSize: 12,
              }}
              title="Toggle theme"
            >
              {theme === 'dark' ? '☀️' : '🌙'}
            </button>
            <div className="topbar-badge">Connected</div>
          </div>
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  )
}

function LoginPage() {
  const navigate = useNavigate()
  const [email, setEmail] = useState('admin@example.com')
  const [password, setPassword] = useState('Admin123!')
  const [error, setError] = useState('')
  const [checkingSetup, setCheckingSetup] = useState(true)

  useEffect(() => {
    // Check if setup is complete
    api.get('/api/v1/setup/check').then(res => {
      if (!res.data.setup_complete) {
        navigate('/setup')
      } else {
        setCheckingSetup(false)
      }
    }).catch(() => {
      setCheckingSetup(false)
    })
  }, [navigate])

  if (checkingSetup) {
    return (
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '100vh',
        background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)',
      }}>
        <div style={{ color: 'white' }}>Loading...</div>
      </div>
    )
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    try {
      const res = await api.post('/api/v1/auth/login', { email, password })
      localStorage.setItem('token', res.data.access_token)
      api.defaults.headers.common.Authorization = `Bearer {res.data.access_token}`
      navigate('/')
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Login failed')
    }
  }

  return (
    <div style={{ display: 'flex', minHeight: '100vh', alignItems: 'center', justifyContent: 'center' }}>
      <form
        onSubmit={handleSubmit}
        style={{
          width: 340,
          padding: 26,
          borderRadius: 16,
          background: 'radial-gradient(circle at 0 0, #1f2937 0, #020617 60%, #020617 100%)',
          color: 'white',
          boxShadow: '0 20px 45px rgba(15,23,42,0.95), 0 0 0 1px rgba(15,23,42,1)',
        }}
      >
        <h2 style={{ marginTop: 0, marginBottom: 16 }}>Honeypot Login</h2>
        <p style={{ marginTop: 0, marginBottom: 16, fontSize: 12, color: '#9ca3af' }}>
        </p>
        {error && <p style={{ color: 'salmon', marginBottom: 12 }}>{error}</p>}
        <label style={{ fontSize: 12 }}>Email</label>
        <input
          value={email}
          onChange={e => setEmail(e.target.value)}
          style={{
            width: '100%',
            marginBottom: 10,
            marginTop: 4,
            padding: '8px 9px',
            borderRadius: 8,
            border: '1px solid #4b5563',
            background: '#020617',
            color: 'white',
          }}
        />
        <label style={{ fontSize: 12 }}>Password</label>
        <input
          type="password"
          value={password}
          onChange={e => setPassword(e.target.value)}
          style={{
            width: '100%',
            marginBottom: 16,
            marginTop: 4,
            padding: '8px 9px',
            borderRadius: 8,
            border: '1px solid #4b5563',
            background: '#020617',
            color: 'white',
          }}
        />
        <button
          type="submit"
          style={{
            width: '100%',
            padding: '9px 10px',
            borderRadius: 999,
            border: 'none',
            background:
              'linear-gradient(90deg, rgba(34,197,94,1) 0%, rgba(22,163,74,1) 40%, rgba(16,185,129,1) 100%)',
            color: '#022c22',
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          Login
        </button>
      </form>
    </div>
  )
}

function DashboardPage() {
  const [stats, setStats] = useState({ nodes: 0, honeypots: 0, sessions: 0, iocs: 0 })
  const [recentEvents, setRecentEvents] = useState<any[]>([])
  const [chartData, setChartData] = useState<any[]>([])
  const [alerts, setAlerts] = useState<any[]>([])
  const [topAttackers, setTopAttackers] = useState<any[]>([])

  const loadData = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      Promise.all([
        api.get('/api/v1/nodes'),
        api.get('/api/v1/honeypots'),
        api.get('/api/v1/sessions?limit=10'),
        api.get('/api/v1/iocs?limit=10'),
        api.get('/api/v1/events?limit=100'),
        api.get('/api/v1/alerts?unread_only=true&limit=10'),
        api.get('/api/v1/attackers/top?limit=10&days=30'),
      ])
        .then(([nodesRes, hpRes, sessionsRes, iocsRes, eventsRes, alertsRes, attackersRes]) => {
          setStats({
            nodes: Array.isArray(nodesRes.data) ? nodesRes.data.length : 0,
            honeypots: Array.isArray(hpRes.data) ? hpRes.data.filter((h: any) => h.status === 'running').length : 0,
            sessions: Array.isArray(sessionsRes.data) ? sessionsRes.data.length : 0,
            iocs: Array.isArray(iocsRes.data) ? iocsRes.data.length : 0,
          })
          const events = Array.isArray(eventsRes.data) ? eventsRes.data : []
          setRecentEvents(events.slice(0, 10))
          setAlerts(Array.isArray(alertsRes.data) ? alertsRes.data : [])

          // Prepare chart data (last 24 hours, grouped by hour)
          const now = new Date()
          const hours = Array.from({ length: 24 }, (_, i) => {
            const hour = new Date(now.getTime() - (23 - i) * 60 * 60 * 1000)
            return {
              time: hour.getHours() + ':00',
              events: 0,
              ssh: 0,
              web: 0,
            }
          })

          events.forEach((evt: any) => {
            const evtTime = new Date(evt.ts)
            const hoursAgo = Math.floor((now.getTime() - evtTime.getTime()) / (60 * 60 * 1000))
            if (hoursAgo >= 0 && hoursAgo < 24) {
              hours[23 - hoursAgo].events++
              if (evt.event_type === 'ssh_connection') hours[23 - hoursAgo].ssh++
              if (evt.event_type === 'web_request') hours[23 - hoursAgo].web++
            }
          })
          setChartData(hours)
          setTopAttackers(Array.isArray(attackersRes.data) ? attackersRes.data : [])
        })
        .catch(() => {})
    }
  }

  useEffect(() => {
    loadData()
  }, [])

  useEffect(() => {
    const interval = setInterval(loadData, 5000)
    return () => clearInterval(interval)
  }, [])

  return (
    <>
      <section>
        <div className="page-title">Threat overview</div>
        <div className="page-subtitle">High‑level telemetry from your deception surface.</div>
      </section>
      <section className="cards-grid">
        <div className="card">
          <div className="card-label">Nodes online</div>
          <div className="card-main">
            <div>
              <div className="card-value">{stats.nodes}</div>
              <div className="card-sub">Agents reporting in</div>
            </div>
            <span className="card-pill">Live</span>
          </div>
        </div>
        <div className="card">
          <div className="card-label">Active honeypots</div>
          <div className="card-main">
            <div>
              <div className="card-value">{stats.honeypots}</div>
              <div className="card-sub">Running decoys</div>
            </div>
            <span className="card-pill">SSH · Web · DB</span>
          </div>
        </div>
        <div className="card">
          <div className="card-label">Sessions</div>
          <div className="card-main">
            <div>
              <div className="card-value">{stats.sessions}</div>
              <div className="card-sub">Attacker touchpoints</div>
            </div>
            <span className="card-pill">{stats.sessions > 0 ? 'Active' : 'Quiet'}</span>
          </div>
        </div>
        <div className="card">
          <div className="card-label">IOC matches</div>
          <div className="card-main">
            <div>
              <div className="card-value">{stats.iocs}</div>
              <div className="card-sub">Correlated indicators</div>
            </div>
            <span className="card-pill">{stats.iocs > 0 ? 'Threats' : 'No hits'}</span>
          </div>
        </div>
      </section>

      {alerts.length > 0 && (
        <section className="panel" style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)' }}>
          <div className="panel-header">
            <div>
              <div className="panel-title" style={{ color: '#fca5a5' }}>⚠️ Active Alerts ({alerts.length})</div>
              <div className="panel-subtitle">High-risk events detected</div>
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {alerts.slice(0, 3).map((alert: any) => (
              <div
                key={alert.id}
                style={{
                  padding: 12,
                  background: 'rgba(15, 23, 42, 0.9)',
                  borderRadius: 8,
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>{alert.title}</div>
                    <div style={{ fontSize: 11, color: '#9ca3af' }}>{alert.message}</div>
                  </div>
                  <span
                    className={`status-pill ${alert.severity === 'critical' ? 'danger' : alert.severity === 'high' ? 'warn' : ''}`}
                  >
                    {alert.severity}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {chartData.length > 0 && (
        <section className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">Event Trends (Last 24 Hours)</div>
              <div className="panel-subtitle">Activity over time</div>
            </div>
          </div>
          <div style={{ height: 300, marginTop: 16 }}>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="time" stroke="#9ca3af" style={{ fontSize: 11 }} />
                <YAxis stroke="#9ca3af" style={{ fontSize: 11 }} />
                <Tooltip
                  contentStyle={{ background: '#020617', border: '1px solid #374151', borderRadius: 8 }}
                  labelStyle={{ color: '#f9fafb' }}
                />
                <Legend />
                <Line type="monotone" dataKey="events" stroke="#22c55e" strokeWidth={2} name="Total Events" />
                <Line type="monotone" dataKey="ssh" stroke="#3b82f6" strokeWidth={2} name="SSH" />
                <Line type="monotone" dataKey="web" stroke="#f59e0b" strokeWidth={2} name="Web" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </section>
      )}

      {topAttackers.length > 0 && (
        <section className="panel" style={{ marginBottom: 24 }}>
          <div className="panel-header">
            <div>
              <div className="panel-title">Top Attackers</div>
              <div className="panel-subtitle">Highest risk IPs based on activity and techniques.</div>
            </div>
          </div>
          <table className="table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Risk Score</th>
                <th>Events</th>
                <th>Honeypots</th>
                <th>MITRE Techniques</th>
                <th>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {topAttackers.map((attacker: any) => (
                <tr key={attacker.ip}>
                  <td style={{ fontFamily: 'monospace', fontSize: 12, fontWeight: 600 }}>{attacker.ip}</td>
                  <td>
                    <span className={`status-pill ${attacker.risk_score >= 70 ? 'error' : attacker.risk_score >= 40 ? 'warn' : ''}`}>
                      {attacker.risk_score}
                    </span>
                  </td>
                  <td>{attacker.total_events}</td>
                  <td>{attacker.honeypots_touched}</td>
                  <td>{attacker.mitre_techniques}</td>
                  <td className="muted" style={{ fontSize: 11 }}>
                    {new Date(attacker.last_seen).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      <section className="panel">
        <div className="panel-header">
          <div>
            <div className="panel-title">Recent activity</div>
            <div className="panel-subtitle">When honeypots receive traffic it will appear here.</div>
          </div>
          <div className="chips-row">
            <span className="chip">SSH</span>
            <span className="chip">Web</span>
            <span className="chip">Database</span>
            <span className="chip">ICS</span>
          </div>
        </div>
        <table className="table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Source</th>
              <th>Type</th>
              <th>Action</th>
              <th>Risk</th>
            </tr>
          </thead>
          <tbody>
            {recentEvents.length === 0 ? (
              <tr>
                <td colSpan={5} className="muted">
                  No activity yet — deploy a node and start a honeypot to see live telemetry.
                </td>
              </tr>
            ) : (
              recentEvents.map(evt => (
                <tr key={evt.id}>
                  <td>{new Date(evt.ts).toLocaleString()}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{evt.src_ip}</td>
                  <td>
                    <span className="chip">{evt.event_type}</span>
                  </td>
                  <td className="muted">{evt.payload?.method || evt.payload?.commands?.length || '-'}</td>
                  <td>
                    <span className={`status-pill ${evt.payload?.score > 50 ? 'danger' : evt.payload?.score > 20 ? 'warn' : ''}`}>
                      {evt.payload?.score || 0}
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </section>
    </>
  )
}

function NodesPage() {
  const [nodes, setNodes] = useState<any[]>([])
  const [showForm, setShowForm] = useState(false)
  const [name, setName] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    loadNodes()
  }, [])

  const loadNodes = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api
        .get('/api/v1/nodes')
        .then(res => setNodes(Array.isArray(res.data) ? res.data : []))
        .catch(() => setNodes([]))
    }
  }

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      await api.post('/api/v1/nodes', { name })
      setName('')
      setShowForm(false)
      loadNodes()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create node')
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <section className="panel">
        <div className="panel-header">
          <div>
            <div className="page-title">Nodes</div>
            <div className="page-subtitle">Lightweight agents that host honeypots on your infrastructure.</div>
          </div>
          <button
            onClick={() => setShowForm(!showForm)}
            style={{
              padding: '6px 12px',
              borderRadius: 8,
              border: '1px solid #22c55e',
              background: 'rgba(34, 197, 94, 0.1)',
              color: '#22c55e',
              cursor: 'pointer',
              fontSize: 12,
            }}
          >
            {showForm ? 'Cancel' : '+ Create Node'}
          </button>
        </div>
        {showForm && (
          <form onSubmit={handleCreate} style={{ marginBottom: 16, padding: 12, border: '1px solid #374151', borderRadius: 8 }}>
            <input
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="Node name (e.g., production-server-01)"
              required
              style={{
                width: '100%',
                padding: '8px 10px',
                borderRadius: 6,
                border: '1px solid #4b5563',
                background: '#020617',
                color: 'white',
                marginBottom: 8,
              }}
            />
            <button
              type="submit"
              disabled={loading}
              style={{
                padding: '6px 12px',
                borderRadius: 6,
                border: 'none',
                background: '#22c55e',
                color: '#022c22',
                cursor: loading ? 'not-allowed' : 'pointer',
                fontSize: 12,
                fontWeight: 600,
              }}
            >
              {loading ? 'Creating...' : 'Create'}
            </button>
          </form>
        )}
        <table className="table">
          <thead>
            <tr>
              <th>Name</th>
              <th>API key</th>
              <th>Last heartbeat</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {nodes.length === 0 ? (
              <tr>
                <td colSpan={5} className="muted">
                  No nodes registered yet. Click "Create Node" above to add one.
                </td>
              </tr>
            ) : (
              nodes.map(node => (
                <tr key={node.id}>
                  <td>{node.name}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{node.api_key?.substring(0, 16)}...</td>
                  <td className="muted">{node.last_heartbeat_at ? new Date(node.last_heartbeat_at).toLocaleString() : 'Never'}</td>
                  <td>
                    <span className="status-pill">{node.last_heartbeat_at ? 'Online' : 'Offline'}</span>
                  </td>
                  <td>
                    <button
                      onClick={async () => {
                        if (confirm(`Are you sure you want to delete node "${node.name}"? This will also delete all associated honeypots.`)) {
                          try {
                            await api.delete(`/api/v1/nodes/${node.id}`)
                            loadNodes()
                          } catch (err: any) {
                            alert(err.response?.data?.detail || 'Failed to delete node')
                          }
                        }
                      }}
                      style={{
                        padding: '3px 8px',
                        fontSize: 11,
                        borderRadius: 4,
                        border: '1px solid #ef4444',
                        background: 'rgba(239, 68, 68, 0.1)',
                        color: '#fca5a5',
                        cursor: 'pointer',
                      }}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </section>
    </>
  )
}

function HoneypotsPage() {
  const [honeypots, setHoneypots] = useState<any[]>([])
  const [nodes, setNodes] = useState<any[]>([])
  const [templates, setTemplates] = useState<any[]>([])
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({ node_id: '', template_id: 1, name: '', listen_ip: '0.0.0.0', listen_port: 22 })
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    loadData()
  }, [])

  const loadData = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      Promise.all([api.get('/api/v1/honeypots'), api.get('/api/v1/nodes'), api.get('/api/v1/templates')])
        .then(([hpRes, nodeRes, templatesRes]) => {
          setHoneypots(Array.isArray(hpRes.data) ? hpRes.data : [])
          setNodes(Array.isArray(nodeRes.data) ? nodeRes.data : [])
          setTemplates(Array.isArray(templatesRes.data) ? templatesRes.data : [])
        })
        .catch(() => {
          setHoneypots([])
          setNodes([])
          setTemplates([])
        })
    }
  }

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!formData.node_id) {
      alert('Please select a node')
      return
    }
    setLoading(true)
    try {
      await api.post('/api/v1/honeypots', {
        ...formData,
        node_id: parseInt(formData.node_id),
        template_id: parseInt(formData.template_id.toString()),
        listen_port: parseInt(formData.listen_port.toString()),
      })
      setFormData({ node_id: '', template_id: templates[0]?.id || 1, name: '', listen_ip: '0.0.0.0', listen_port: 22 })
      setShowForm(false)
      loadData()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create honeypot')
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <section className="panel">
        <div className="panel-header">
          <div>
            <div className="page-title">Honeypots</div>
            <div className="page-subtitle">Defined decoys and their deployment status.</div>
          </div>
          <button
            onClick={() => setShowForm(!showForm)}
            disabled={nodes.length === 0}
            style={{
              padding: '6px 12px',
              borderRadius: 8,
              border: '1px solid #22c55e',
              background: nodes.length === 0 ? 'rgba(34, 197, 94, 0.05)' : 'rgba(34, 197, 94, 0.1)',
              color: nodes.length === 0 ? '#6b7280' : '#22c55e',
              cursor: nodes.length === 0 ? 'not-allowed' : 'pointer',
              fontSize: 12,
            }}
          >
            {showForm ? 'Cancel' : '+ Create Honeypot'}
          </button>
        </div>
        {nodes.length === 0 && (
          <div style={{ padding: 12, marginBottom: 16, background: 'rgba(234, 179, 8, 0.1)', border: '1px solid rgba(234, 179, 8, 0.3)', borderRadius: 8, fontSize: 12, color: '#fef3c7' }}>
            Create a Node first before creating honeypots.
          </div>
        )}
        {showForm && (
          <form onSubmit={handleCreate} style={{ marginBottom: 16, padding: 12, border: '1px solid #374151', borderRadius: 8 }}>
            <select
              value={formData.node_id}
              onChange={e => setFormData({ ...formData, node_id: e.target.value })}
              required
              style={{
                width: '100%',
                padding: '8px 10px',
                borderRadius: 6,
                border: '1px solid #4b5563',
                background: '#020617',
                color: 'white',
                marginBottom: 8,
              }}
            >
              <option value="">Select Node</option>
              {nodes.map(n => (
                <option key={n.id} value={n.id}>
                  {n.name}
                </option>
              ))}
            </select>
            <select
              value={formData.template_id}
              onChange={e => {
                const selectedTemplate = templates.find(t => t.id === parseInt(e.target.value))
                let defaultPort = 22
                if (selectedTemplate) {
                  if (selectedTemplate.type === 'smtp') defaultPort = 25
                  else if (selectedTemplate.type === 'web') defaultPort = 80
                  else if (selectedTemplate.type === 'db') defaultPort = 3306
                  else if (selectedTemplate.type === 'ics') defaultPort = 502
                }
                setFormData({ ...formData, template_id: parseInt(e.target.value), listen_port: defaultPort })
              }}
              required
              style={{
                width: '100%',
                padding: '8px 10px',
                borderRadius: 6,
                border: '1px solid #4b5563',
                background: '#020617',
                color: 'white',
                marginBottom: 8,
              }}
            >
              {templates.map(t => (
                <option key={t.id} value={t.id}>
                  {t.name} ({t.type})
                </option>
              ))}
            </select>
            <input
              value={formData.name}
              onChange={e => setFormData({ ...formData, name: e.target.value })}
              placeholder="Honeypot name (e.g., ssh-decoy-01)"
              required
              style={{
                width: '100%',
                padding: '8px 10px',
                borderRadius: 6,
                border: '1px solid #4b5563',
                background: '#020617',
                color: 'white',
                marginBottom: 8,
              }}
            />
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 8 }}>
              <input
                value={formData.listen_ip}
                onChange={e => setFormData({ ...formData, listen_ip: e.target.value })}
                placeholder="Listen IP"
                style={{
                  padding: '8px 10px',
                  borderRadius: 6,
                  border: '1px solid #4b5563',
                  background: '#020617',
                  color: 'white',
                }}
              />
              <input
                type="number"
                value={formData.listen_port}
                onChange={e => setFormData({ ...formData, listen_port: parseInt(e.target.value) || 22 })}
                placeholder="Port"
                required
                style={{
                  padding: '8px 10px',
                  borderRadius: 6,
                  border: '1px solid #4b5563',
                  background: '#020617',
                  color: 'white',
                }}
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              style={{
                padding: '6px 12px',
                borderRadius: 6,
                border: 'none',
                background: '#22c55e',
                color: '#022c22',
                cursor: loading ? 'not-allowed' : 'pointer',
                fontSize: 12,
                fontWeight: 600,
              }}
            >
              {loading ? 'Creating...' : 'Create'}
            </button>
          </form>
        )}
        <table className="table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Node</th>
              <th>Profile</th>
              <th>Listen</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {honeypots.length === 0 ? (
              <tr>
                <td colSpan={6} className="muted">
                  No honeypots yet. Click "Create Honeypot" above to add one.
                </td>
              </tr>
            ) : (
              honeypots.map(hp => (
                <tr key={hp.id}>
                  <td>{hp.name}</td>
                  <td>{nodes.find(n => n.id === hp.node_id)?.name || `Node ${hp.node_id}`}</td>
                  <td className="muted">Template {hp.template_id}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: 11 }}>
                    {hp.listen_ip}:{hp.listen_port}
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                      <span className={`status-pill ${hp.status === 'running' ? '' : 'warn'}`}>
                        {hp.status || 'stopped'}
                      </span>
                      {hp.status === 'running' ? (
                        <button
                          onClick={async () => {
                            try {
                              await api.post(`/api/v1/honeypots/${hp.id}/stop`)
                              loadData()
                            } catch (err: any) {
                              alert(err.response?.data?.detail || 'Failed to stop')
                            }
                          }}
                          style={{
                            padding: '3px 8px',
                            fontSize: 11,
                            borderRadius: 4,
                            border: '1px solid #ef4444',
                            background: 'rgba(239, 68, 68, 0.1)',
                            color: '#fca5a5',
                            cursor: 'pointer',
                          }}
                        >
                          Stop
                        </button>
                      ) : (
                        <button
                          onClick={async () => {
                            try {
                              await api.post(`/api/v1/honeypots/${hp.id}/start`)
                              loadData()
                            } catch (err: any) {
                              alert(err.response?.data?.detail || 'Failed to start')
                            }
                          }}
                          style={{
                            padding: '3px 8px',
                            fontSize: 11,
                            borderRadius: 4,
                            border: '1px solid #22c55e',
                            background: 'rgba(34, 197, 94, 0.1)',
                            color: '#86efac',
                            cursor: 'pointer',
                          }}
                        >
                          Start
                        </button>
                      )}
                    </div>
                  </td>
                  <td>
                    <button
                      onClick={async () => {
                        if (confirm(`Are you sure you want to delete honeypot "${hp.name}"? This will also delete all associated sessions and events.`)) {
                          try {
                            await api.delete(`/api/v1/honeypots/${hp.id}`)
                            loadData()
                          } catch (err: any) {
                            alert(err.response?.data?.detail || 'Failed to delete honeypot')
                          }
                        }
                      }}
                      style={{
                        padding: '3px 8px',
                        fontSize: 11,
                        borderRadius: 4,
                        border: '1px solid #ef4444',
                        background: 'rgba(239, 68, 68, 0.1)',
                        color: '#fca5a5',
                        cursor: 'pointer',
                      }}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </section>
    </>
  )
}

function EventsPage() {
  const [events, setEvents] = useState<any[]>([])
  const [filteredEvents, setFilteredEvents] = useState<any[]>([])
  const [searchTerm, setSearchTerm] = useState('')
  const [filterType, setFilterType] = useState<string>('all')

  useEffect(() => {
    loadEvents()
    const interval = setInterval(loadEvents, 5000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    let filtered = events
    if (searchTerm) {
      filtered = filtered.filter(e => 
        e.src_ip.toLowerCase().includes(searchTerm.toLowerCase()) ||
        e.event_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
        JSON.stringify(e.payload).toLowerCase().includes(searchTerm.toLowerCase())
      )
    }
    if (filterType !== 'all') {
      filtered = filtered.filter(e => e.event_type === filterType)
    }
    setFilteredEvents(filtered)
  }, [events, searchTerm, filterType])

  const loadEvents = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api
        .get('/api/v1/events?limit=100')
        .then(res => setEvents(Array.isArray(res.data) ? res.data : []))
        .catch(() => setEvents([]))
    }
  }

  const exportCSV = () => {
    const headers = ['Time', 'Source IP', 'Honeypot', 'Type', 'Details']
    const rows = filteredEvents.map(e => [
      new Date(e.ts).toISOString(),
      e.src_ip,
      `HP #${e.honeypot_id}`,
      e.event_type,
      JSON.stringify(e.payload),
    ])
    const csv = [headers.join(','), ...rows.map(r => r.map(c => `"${c}"`).join(','))].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `events_${new Date().toISOString().split('T')[0]}.csv`
    a.click()
  }

  const exportJSON = () => {
    const json = JSON.stringify(filteredEvents, null, 2)
    const blob = new Blob([json], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `events_${new Date().toISOString().split('T')[0]}.json`
    a.click()
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Events</div>
          <div className="page-subtitle">Low level telemetry from attacker interactions.</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={exportCSV}
            disabled={filteredEvents.length === 0}
            style={{
              padding: '6px 12px',
              fontSize: 12,
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: 'rgba(15, 23, 42, 0.9)',
              color: '#e5e7eb',
              cursor: events.length === 0 ? 'not-allowed' : 'pointer',
            }}
          >
            Export CSV
          </button>
          <button
            onClick={exportJSON}
            disabled={filteredEvents.length === 0}
            style={{
              padding: '6px 12px',
              fontSize: 12,
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: 'rgba(15, 23, 42, 0.9)',
              color: '#e5e7eb',
              cursor: events.length === 0 ? 'not-allowed' : 'pointer',
            }}
          >
            Export JSON
          </button>
        </div>
      </div>
      <div style={{ marginBottom: 16, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <input
          type="text"
          placeholder="Search by IP, type, or details..."
          value={searchTerm}
          onChange={e => setSearchTerm(e.target.value)}
          style={{
            flex: 1,
            minWidth: 200,
            padding: '8px 12px',
            borderRadius: 6,
            border: '1px solid #4b5563',
            background: '#020617',
            color: 'white',
            fontSize: 12,
          }}
        />
        <div style={{ display: 'flex', gap: 4 }}>
          {['all', 'ssh_connection', 'web_request', 'db_connection'].map(type => (
            <button
              key={type}
              onClick={() => setFilterType(type)}
              style={{
                padding: '6px 12px',
                fontSize: 11,
                borderRadius: 6,
                border: '1px solid #4b5563',
                background: filterType === type ? '#22c55e' : 'rgba(15, 23, 42, 0.9)',
                color: filterType === type ? '#022c22' : '#e5e7eb',
                cursor: 'pointer',
                textTransform: 'capitalize',
              }}
            >
              {type === 'all' ? 'All' : type.replace('_', ' ')}
            </button>
          ))}
        </div>
      </div>
      <div style={{ marginBottom: 8, fontSize: 12, color: '#9ca3af' }}>
        Showing {filteredEvents.length} of {events.length} events
      </div>
      <table className="table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Source</th>
            <th>Honeypot</th>
            <th>Type</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          {filteredEvents.length === 0 ? (
            <tr>
              <td colSpan={5} className="muted">
                {events.length === 0 ? 'No events recorded yet.' : 'No events match your filters.'}
              </td>
            </tr>
          ) : (
            filteredEvents.map(evt => (
              <tr key={evt.id}>
                <td>{new Date(evt.ts).toLocaleString()}</td>
                <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{evt.src_ip}</td>
                <td className="muted">HP #{evt.honeypot_id}</td>
                <td>
                  <span className="chip">{evt.event_type}</span>
                </td>
                <td className="muted" style={{ fontSize: 11 }}>
                  {evt.payload?.method || evt.payload?.path || JSON.stringify(evt.payload).substring(0, 50)}
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </section>
  )
}

function IocsPage() {
  const [iocs, setIocs] = useState<any[]>([])
  const [filteredIocs, setFilteredIocs] = useState<any[]>([])
  const [searchTerm, setSearchTerm] = useState('')
  const [filterType, setFilterType] = useState<string>('all')
  const [minScore, setMinScore] = useState(0)

  useEffect(() => {
    loadIocs()
    const interval = setInterval(loadIocs, 5000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    let filtered = iocs
    if (searchTerm) {
      filtered = filtered.filter(i => 
        i.value.toLowerCase().includes(searchTerm.toLowerCase()) ||
        i.ioc_type.toLowerCase().includes(searchTerm.toLowerCase())
      )
    }
    if (filterType !== 'all') {
      filtered = filtered.filter(i => i.ioc_type === filterType)
    }
    filtered = filtered.filter(i => i.score >= minScore)
    setFilteredIocs(filtered)
  }, [iocs, searchTerm, filterType, minScore])

  const loadIocs = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api
        .get('/api/v1/iocs?limit=100')
        .then(res => setIocs(Array.isArray(res.data) ? res.data : []))
        .catch(() => setIocs([]))
    }
  }

  const exportCSV = () => {
    const headers = ['Type', 'Value', 'First Seen', 'Last Seen', 'Seen Count', 'Score']
    const rows = filteredIocs.map(i => [
      i.ioc_type,
      i.value,
      new Date(i.first_seen).toISOString(),
      new Date(i.last_seen).toISOString(),
      i.seen_count,
      i.score,
    ])
    const csv = [headers.join(','), ...rows.map(r => r.map(c => `"${c}"`).join(','))].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `iocs_${new Date().toISOString().split('T')[0]}.csv`
    a.click()
  }

  const exportJSON = () => {
    const json = JSON.stringify(filteredIocs, null, 2)
    const blob = new Blob([json], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `iocs_${new Date().toISOString().split('T')[0]}.json`
    a.click()
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Indicators of Compromise</div>
          <div className="page-subtitle">Correlated malicious IPs, URLs, hashes and credentials.</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={exportCSV}
            disabled={filteredIocs.length === 0}
            style={{
              padding: '6px 12px',
              fontSize: 12,
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: 'rgba(15, 23, 42, 0.9)',
              color: '#e5e7eb',
              cursor: iocs.length === 0 ? 'not-allowed' : 'pointer',
            }}
          >
            Export CSV
          </button>
          <button
            onClick={exportJSON}
            disabled={filteredIocs.length === 0}
            style={{
              padding: '6px 12px',
              fontSize: 12,
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: 'rgba(15, 23, 42, 0.9)',
              color: '#e5e7eb',
              cursor: filteredIocs.length === 0 ? 'not-allowed' : 'pointer',
            }}
          >
            Export JSON
          </button>
        </div>
      </div>
      <div style={{ marginBottom: 16, display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <input
          type="text"
          placeholder="Search by value or type..."
          value={searchTerm}
          onChange={e => setSearchTerm(e.target.value)}
          style={{
            flex: 1,
            minWidth: 200,
            padding: '8px 12px',
            borderRadius: 6,
            border: '1px solid #4b5563',
            background: '#020617',
            color: 'white',
            fontSize: 12,
          }}
        />
        <div style={{ display: 'flex', gap: 4 }}>
          {['all', 'ip', 'url', 'hash', 'credential'].map(type => (
            <button
              key={type}
              onClick={() => setFilterType(type)}
              style={{
                padding: '6px 12px',
                fontSize: 11,
                borderRadius: 6,
                border: '1px solid #4b5563',
                background: filterType === type ? '#22c55e' : 'rgba(15, 23, 42, 0.9)',
                color: filterType === type ? '#022c22' : '#e5e7eb',
                cursor: 'pointer',
                textTransform: 'capitalize',
              }}
            >
              {type === 'all' ? 'All' : type}
            </button>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <label style={{ fontSize: 11, color: '#9ca3af' }}>Min Score:</label>
          <input
            type="number"
            min="0"
            max="100"
            value={minScore}
            onChange={e => setMinScore(parseInt(e.target.value) || 0)}
            style={{
              width: 60,
              padding: '6px 8px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              fontSize: 11,
            }}
          />
        </div>
      </div>
      <div style={{ marginBottom: 8, fontSize: 12, color: '#9ca3af' }}>
        Showing {filteredIocs.length} of {iocs.length} IOCs
      </div>
      <table className="table">
        <thead>
          <tr>
            <th>Type</th>
            <th>Value</th>
            <th>First seen</th>
            <th>Last seen</th>
            <th>Seen</th>
            <th>Score</th>
          </tr>
        </thead>
        <tbody>
          {filteredIocs.length === 0 ? (
            <tr>
              <td colSpan={6} className="muted">
                {iocs.length === 0 ? 'No IOCs yet.' : 'No IOCs match your filters.'}
              </td>
            </tr>
          ) : (
            filteredIocs.map(ioc => (
              <tr key={ioc.id}>
                <td>
                  <span className="chip">{ioc.ioc_type}</span>
                </td>
                <td style={{ fontFamily: 'monospace', fontSize: 11, maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {ioc.value}
                </td>
                <td className="muted" style={{ fontSize: 11 }}>
                  {new Date(ioc.first_seen).toLocaleString()}
                </td>
                <td className="muted" style={{ fontSize: 11 }}>
                  {new Date(ioc.last_seen).toLocaleString()}
                </td>
                <td className="muted">{ioc.seen_count}x</td>
                <td>
                  <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                    <span
                      className={`status-pill ${ioc.score > 70 ? 'danger' : ioc.score > 40 ? 'warn' : ''}`}
                    >
                      {ioc.score}
                    </span>
                    {ioc.ioc_type === 'ip' && (
                      <button
                        onClick={async () => {
                          try {
                            await api.post(`/api/v1/iocs/${ioc.id}/enrich`)
                            alert('IOC enriched successfully!')
                            loadIocs()
                          } catch (err: any) {
                            alert(err.response?.data?.detail || 'Failed to enrich IOC')
                          }
                        }}
                        style={{
                          padding: '2px 6px',
                          fontSize: 10,
                          borderRadius: 4,
                          border: '1px solid #4b5563',
                          background: 'rgba(15, 23, 42, 0.9)',
                          color: '#e5e7eb',
                          cursor: 'pointer',
                        }}
                        title="Enrich with Threat Intelligence"
                      >
                        🔍
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </section>
  )
}

function ThreatMapPage() {
  const [iocs, setIocs] = useState<any[]>([])
  const [events, setEvents] = useState<any[]>([])

  useEffect(() => {
    loadData()
    const interval = setInterval(loadData, 10000)
    return () => clearInterval(interval)
  }, [])

  const loadData = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      Promise.all([api.get('/api/v1/iocs?limit=100'), api.get('/api/v1/events?limit=100')])
        .then(([iocsRes, eventsRes]) => {
          setIocs(Array.isArray(iocsRes.data) ? iocsRes.data.filter((i: any) => i.ioc_type === 'ip') : [])
          setEvents(Array.isArray(eventsRes.data) ? eventsRes.data : [])
        })
        .catch(() => {
          setIocs([])
          setEvents([])
        })
    }
  }

  // Simple GeoIP simulation (in production, use a real GeoIP service)
  const getIPLocation = (ip: string) => {
    // Simulate location based on IP patterns
    if (ip.startsWith('127.') || ip.startsWith('::1') || ip.startsWith('172.18.')) {
      return { lat: 39.9042, lng: 32.4074, country: 'Turkey', city: 'Ankara' } // Default to Turkey
    }
    // Random locations for visualization
    const locations = [
      { lat: 40.7128, lng: -74.0060, country: 'USA', city: 'New York' },
      { lat: 51.5074, lng: -0.1278, country: 'UK', city: 'London' },
      { lat: 55.7558, lng: 37.6173, country: 'Russia', city: 'Moscow' },
      { lat: 35.6762, lng: 139.6503, country: 'Japan', city: 'Tokyo' },
      { lat: 52.5200, lng: 13.4050, country: 'Germany', city: 'Berlin' },
    ]
    const hash = ip.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0)
    return locations[hash % locations.length]
  }

  const uniqueIPs = Array.from(new Set(iocs.map(i => i.value)))
  const ipData = uniqueIPs.map(ip => {
    const ioc = iocs.find(i => i.value === ip)
    const location = getIPLocation(ip)
    return {
      ip,
      location,
      score: ioc?.score || 0,
      seen: ioc?.seen_count || 0,
    }
  })

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Threat Map</div>
          <div className="page-subtitle">Geographic visualization of attack sources.</div>
        </div>
      </div>
      <div style={{ marginBottom: 16, padding: 16, background: 'rgba(15, 23, 42, 0.5)', borderRadius: 8 }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 16 }}>
          <div>
            <div style={{ fontSize: 11, color: '#9ca3af', marginBottom: 4 }}>Total IPs</div>
            <div style={{ fontSize: 24, fontWeight: 600, color: '#e5e7eb' }}>{uniqueIPs.length}</div>
          </div>
          <div>
            <div style={{ fontSize: 11, color: '#9ca3af', marginBottom: 4 }}>High Risk</div>
            <div style={{ fontSize: 24, fontWeight: 600, color: '#ef4444' }}>
              {ipData.filter(i => i.score > 70).length}
            </div>
          </div>
          <div>
            <div style={{ fontSize: 11, color: '#9ca3af', marginBottom: 4 }}>Countries</div>
            <div style={{ fontSize: 24, fontWeight: 600, color: '#e5e7eb' }}>
              {new Set(ipData.map(i => i.location.country)).size}
            </div>
          </div>
        </div>
      </div>
      <div
        style={{
          height: 500,
          background: 'rgba(15, 23, 42, 0.5)',
          borderRadius: 8,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          border: '1px solid #374151',
          position: 'relative',
          overflow: 'hidden',
        }}
      >
        {/* Simple map visualization */}
        <div style={{ position: 'relative', width: '100%', height: '100%' }}>
          {ipData.map((data, idx) => (
            <div
              key={idx}
              style={{
                position: 'absolute',
                left: `${50 + (data.location.lng / 180) * 40}%`,
                top: `${50 - (data.location.lat / 90) * 40}%`,
                width: Math.max(8, Math.min(20, data.score / 5)),
                height: Math.max(8, Math.min(20, data.score / 5)),
                borderRadius: '50%',
                background: data.score > 70 ? '#ef4444' : data.score > 40 ? '#f59e0b' : '#22c55e',
                border: '2px solid rgba(255, 255, 255, 0.3)',
                cursor: 'pointer',
                boxShadow: `0 0 ${data.score / 2}px ${data.score > 70 ? '#ef4444' : data.score > 40 ? '#f59e0b' : '#22c55e'}`,
              }}
              title={`${data.ip} - ${data.location.city}, ${data.location.country} (Score: ${data.score})`}
            />
          ))}
          <div
            style={{
              position: 'absolute',
              bottom: 16,
              left: 16,
              padding: '8px 12px',
              background: 'rgba(15, 23, 42, 0.9)',
              borderRadius: 6,
              fontSize: 11,
              color: '#9ca3af',
            }}
          >
            🗺️ Interactive Threat Map ({ipData.length} IPs visualized)
          </div>
        </div>
      </div>
      <div style={{ marginTop: 16 }}>
        <h3 style={{ fontSize: 14, marginBottom: 12, color: '#e5e7eb' }}>Top Threat IPs</h3>
        <table className="table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Location</th>
              <th>Score</th>
              <th>Seen</th>
            </tr>
          </thead>
          <tbody>
            {ipData
              .sort((a, b) => b.score - a.score)
              .slice(0, 10)
              .map((data, idx) => (
                <tr key={idx}>
                  <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{data.ip}</td>
                  <td className="muted" style={{ fontSize: 11 }}>
                    {data.location.city}, {data.location.country}
                  </td>
                  <td>
                    <span
                      className={`status-pill ${data.score > 70 ? 'danger' : data.score > 40 ? 'warn' : ''}`}
                    >
                      {data.score}
                    </span>
                  </td>
                  <td className="muted">{data.seen}x</td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}

function SettingsPage() {
  const [settings, setSettings] = useState({
    smtp_host: '',
    smtp_port: 587,
    smtp_user: '',
    smtp_password: '',
    alert_email: '',
  })
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    // Load settings from environment or localStorage
    const savedSettings = localStorage.getItem('settings')
    if (savedSettings) {
      setSettings(JSON.parse(savedSettings))
    }
  }, [])

  const handleSave = () => {
    localStorage.setItem('settings', JSON.stringify(settings))
    setSaved(true)
    setTimeout(() => setSaved(false), 3000)
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Settings</div>
          <div className="page-subtitle">Configure platform settings and notifications.</div>
        </div>
      </div>
      <div style={{ maxWidth: 600 }}>
        <div style={{ marginBottom: 24 }}>
          <h3 style={{ fontSize: 14, marginBottom: 12, color: '#e5e7eb' }}>Email Notifications</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div>
              <label style={{ fontSize: 11, color: '#9ca3af', marginBottom: 4, display: 'block' }}>SMTP Host</label>
              <input
                type="text"
                value={settings.smtp_host}
                onChange={e => setSettings({ ...settings, smtp_host: e.target.value })}
                placeholder="smtp.gmail.com"
                style={{
                  width: '100%',
                  padding: '8px 12px',
                  borderRadius: 6,
                  border: '1px solid #4b5563',
                  background: '#020617',
                  color: 'white',
                  fontSize: 12,
                }}
              />
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <div>
                <label style={{ fontSize: 11, color: '#9ca3af', marginBottom: 4, display: 'block' }}>SMTP Port</label>
                <input
                  type="number"
                  value={settings.smtp_port}
                  onChange={e => setSettings({ ...settings, smtp_port: parseInt(e.target.value) || 587 })}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: 6,
                    border: '1px solid #4b5563',
                    background: '#020617',
                    color: 'white',
                    fontSize: 12,
                  }}
                />
              </div>
            </div>
            <div>
              <label style={{ fontSize: 11, color: '#9ca3af', marginBottom: 4, display: 'block' }}>SMTP User</label>
              <input
                type="text"
                value={settings.smtp_user}
                onChange={e => setSettings({ ...settings, smtp_user: e.target.value })}
                placeholder="your-email@gmail.com"
                style={{
                  width: '100%',
                  padding: '8px 12px',
                  borderRadius: 6,
                  border: '1px solid #4b5563',
                  background: '#020617',
                  color: 'white',
                  fontSize: 12,
                }}
              />
            </div>
            <div>
              <label style={{ fontSize: 11, color: '#9ca3af', marginBottom: 4, display: 'block' }}>
                SMTP Password
              </label>
              <input
                type="password"
                value={settings.smtp_password}
                onChange={e => setSettings({ ...settings, smtp_password: e.target.value })}
                placeholder="••••••••"
                style={{
                  width: '100%',
                  padding: '8px 12px',
                  borderRadius: 6,
                  border: '1px solid #4b5563',
                  background: '#020617',
                  color: 'white',
                  fontSize: 12,
                }}
              />
            </div>
            <div>
              <label style={{ fontSize: 11, color: '#9ca3af', marginBottom: 4, display: 'block' }}>
                Alert Email
              </label>
              <input
                type="email"
                value={settings.alert_email}
                onChange={e => setSettings({ ...settings, alert_email: e.target.value })}
                placeholder="alerts@example.com"
                style={{
                  width: '100%',
                  padding: '8px 12px',
                  borderRadius: 6,
                  border: '1px solid #4b5563',
                  background: '#020617',
                  color: 'white',
                  fontSize: 12,
                }}
              />
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <button
            onClick={handleSave}
            style={{
              padding: '8px 16px',
              borderRadius: 6,
              border: 'none',
              background: '#22c55e',
              color: '#022c22',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Save Settings
          </button>
          {saved && (
            <span style={{ fontSize: 12, color: '#22c55e' }}>✓ Settings saved!</span>
          )}
        </div>
      </div>
    </section>
  )
}

function BlockedIPsPage() {
  const [blockedIPs, setBlockedIPs] = useState<any[]>([])
  const [showForm, setShowForm] = useState(false)
  const [ip, setIP] = useState('')
  const [reason, setReason] = useState('')

  useEffect(() => {
    loadBlockedIPs()
    const interval = setInterval(loadBlockedIPs, 5000)
    return () => clearInterval(interval)
  }, [])

  const loadBlockedIPs = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api
        .get('/api/v1/blocked-ips')
        .then(res => setBlockedIPs(Array.isArray(res.data) ? res.data : []))
        .catch(() => setBlockedIPs([]))
    }
  }

  const handleBlock = async () => {
    if (!ip) {
      alert('Please enter an IP address')
      return
    }
    try {
      await api.post('/api/v1/blocked-ips', null, { params: { ip, reason: reason || 'Manual block' } })
      setIP('')
      setReason('')
      setShowForm(false)
      loadBlockedIPs()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to block IP')
    }
  }

  const handleUnblock = async (ip: string) => {
    if (!confirm(`Unblock ${ip}?`)) return
    try {
      await api.delete(`/api/v1/blocked-ips/${ip}`)
      loadBlockedIPs()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to unblock IP')
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Blocked IPs</div>
          <div className="page-subtitle">Manage blocked IP addresses.</div>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          style={{
            padding: '6px 12px',
            borderRadius: 8,
            border: '1px solid #ef4444',
            background: 'rgba(239, 68, 68, 0.1)',
            color: '#ef4444',
            cursor: 'pointer',
            fontSize: 12,
          }}
        >
          {showForm ? 'Cancel' : '+ Block IP'}
        </button>
      </div>
      {showForm && (
        <div style={{ marginBottom: 16, padding: 12, border: '1px solid #374151', borderRadius: 8 }}>
          <input
            type="text"
            value={ip}
            onChange={e => setIP(e.target.value)}
            placeholder="IP Address (e.g., 192.168.1.100)"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <input
            type="text"
            value={reason}
            onChange={e => setReason(e.target.value)}
            placeholder="Reason (optional)"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <button
            onClick={handleBlock}
            style={{
              padding: '6px 12px',
              borderRadius: 6,
              border: 'none',
              background: '#ef4444',
              color: 'white',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Block IP
          </button>
        </div>
      )}
      <table className="table">
        <thead>
          <tr>
            <th>IP Address</th>
            <th>Reason</th>
            <th>Blocked At</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {blockedIPs.length === 0 ? (
            <tr>
              <td colSpan={4} className="muted">
                No blocked IPs.
              </td>
            </tr>
          ) : (
            blockedIPs.map(bip => (
              <tr key={bip.id}>
                <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{bip.ip}</td>
                <td className="muted" style={{ fontSize: 11 }}>
                  {bip.reason}
                </td>
                <td className="muted" style={{ fontSize: 11 }}>
                  {new Date(bip.blocked_at).toLocaleString()}
                </td>
                <td>
                  <button
                    onClick={() => handleUnblock(bip.ip)}
                    style={{
                      padding: '4px 8px',
                      fontSize: 11,
                      borderRadius: 4,
                      border: '1px solid #4b5563',
                      background: 'rgba(15, 23, 42, 0.9)',
                      color: '#e5e7eb',
                      cursor: 'pointer',
                    }}
                  >
                    Unblock
                  </button>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </section>
  )
}

function ReportsPage() {
  const [generating, setGenerating] = useState(false)
  const [scheduledReports, setScheduledReports] = useState<any[]>([])
  const [showScheduledForm, setShowScheduledForm] = useState(false)
  const [scheduledFormData, setScheduledFormData] = useState({
    name: '',
    schedule_type: 'daily',
    format: 'pdf',
    recipients: '',
    enabled: true,
  })

  useEffect(() => {
    loadScheduledReports()
    const interval = setInterval(loadScheduledReports, 10000)
    return () => clearInterval(interval)
  }, [])

  const loadScheduledReports = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api
        .get('/api/v1/scheduled-reports')
        .then(res => setScheduledReports(Array.isArray(res.data) ? res.data : []))
        .catch(() => setScheduledReports([]))
    }
  }

  const handleCreateScheduled = async () => {
    try {
      const recipients = scheduledFormData.recipients.split(',').map(e => e.trim()).filter(e => e)
      await api.post('/api/v1/scheduled-reports', {
        name: scheduledFormData.name,
        schedule_type: scheduledFormData.schedule_type,
        format: scheduledFormData.format,
        recipients,
        enabled: scheduledFormData.enabled,
      })
      setScheduledFormData({ name: '', schedule_type: 'daily', format: 'pdf', recipients: '', enabled: true })
      setShowScheduledForm(false)
      loadScheduledReports()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create scheduled report')
    }
  }

  const handleDeleteScheduled = async (reportId: number) => {
    if (!confirm('Delete this scheduled report?')) return
    try {
      await api.delete(`/api/v1/scheduled-reports/${reportId}`)
      loadScheduledReports()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to delete scheduled report')
    }
  }

  const generateReport = async (format: string) => {
    setGenerating(true)
    try {
      if (format === 'pdf') {
        // PDF requires blob response
        const res = await api.get('/api/v1/reports/events', { 
          params: { format: 'pdf' },
          responseType: 'blob'
        })
        const blob = new Blob([res.data], { type: 'application/pdf' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `security_report_${new Date().toISOString().split('T')[0]}.pdf`
        a.click()
        URL.revokeObjectURL(url)
      } else if (format === 'html') {
        const res = await api.get('/api/v1/reports/events', { params: { format: 'html' } })
        const blob = new Blob([res.data], { type: 'text/html' })
        const url = URL.createObjectURL(blob)
        window.open(url, '_blank')
      } else {
        const res = await api.get('/api/v1/reports/events', { params: { format: 'json' } })
        const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: 'application/json' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `events_report_${new Date().toISOString().split('T')[0]}.json`
        a.click()
      }
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to generate report')
    } finally {
      setGenerating(false)
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Reports</div>
          <div className="page-subtitle">Generate and download security reports.</div>
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: 16 }}>
        <div style={{ padding: 20, border: '1px solid #374151', borderRadius: 8, background: 'rgba(15, 23, 42, 0.5)' }}>
          <h3 style={{ fontSize: 14, marginBottom: 8, color: '#e5e7eb' }}>Events Report</h3>
          <p style={{ fontSize: 11, color: '#9ca3af', marginBottom: 12 }}>
            Generate a comprehensive report of all security events.
          </p>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button
              onClick={() => generateReport('pdf')}
              disabled={generating}
              style={{
                padding: '8px 16px',
                borderRadius: 6,
                border: 'none',
                background: '#ef4444',
                color: 'white',
                fontSize: 12,
                fontWeight: 600,
                cursor: generating ? 'not-allowed' : 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 6,
              }}
            >
              📄 {generating ? 'Generating...' : 'PDF Report'}
            </button>
            <button
              onClick={() => generateReport('html')}
              disabled={generating}
              style={{
                padding: '8px 16px',
                borderRadius: 6,
                border: 'none',
                background: '#22c55e',
                color: '#022c22',
                fontSize: 12,
                fontWeight: 600,
                cursor: generating ? 'not-allowed' : 'pointer',
              }}
            >
              {generating ? 'Generating...' : 'HTML Report'}
            </button>
            <button
              onClick={() => generateReport('json')}
              disabled={generating}
              style={{
                padding: '8px 16px',
                borderRadius: 6,
                border: '1px solid #4b5563',
                background: 'rgba(15, 23, 42, 0.9)',
                color: '#e5e7eb',
                fontSize: 12,
                cursor: generating ? 'not-allowed' : 'pointer',
              }}
            >
              JSON Report
            </button>
          </div>
        </div>
      </div>
    </section>
  )
}

function AlertRulesPage() {
  const [rules, setRules] = useState<any[]>([])
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({
    name: '',
    enabled: true,
    conditions: { min_score: 70, min_seen_count: 5 },
    actions: { block_ip: false, send_email: false, webhook_url: '', alert_email: '', severity: 'high' },
  })

  useEffect(() => {
    loadRules()
    const interval = setInterval(loadRules, 5000)
    return () => clearInterval(interval)
  }, [])

  const loadRules = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api
        .get('/api/v1/alert-rules')
        .then(res => setRules(Array.isArray(res.data) ? res.data : []))
        .catch(() => setRules([]))
    }
  }

  const handleCreate = async () => {
    try {
      await api.post('/api/v1/alert-rules', formData)
      setFormData({
        name: '',
        enabled: true,
        conditions: { min_score: 70, min_seen_count: 5 },
        actions: { block_ip: false, send_email: false, webhook_url: '', alert_email: '', severity: 'high' },
      })
      setShowForm(false)
      loadRules()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create rule')
    }
  }

  const handleToggle = async (ruleId: number, enabled: boolean) => {
    try {
      await api.put(`/api/v1/alert-rules/${ruleId}`, null, { params: { enabled: !enabled } })
      loadRules()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to update rule')
    }
  }

  const handleDelete = async (ruleId: number) => {
    if (!confirm('Delete this alert rule?')) return
    try {
      await api.delete(`/api/v1/alert-rules/${ruleId}`)
      loadRules()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to delete rule')
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Alert Rules</div>
          <div className="page-subtitle">Automated response rules for events and IOCs.</div>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          style={{
            padding: '6px 12px',
            borderRadius: 8,
            border: '1px solid #22c55e',
            background: 'rgba(34, 197, 94, 0.1)',
            color: '#22c55e',
            cursor: 'pointer',
            fontSize: 12,
          }}
        >
          {showForm ? 'Cancel' : '+ Create Rule'}
        </button>
      </div>
      {showForm && (
        <div style={{ marginBottom: 16, padding: 16, border: '1px solid #374151', borderRadius: 8 }}>
          <input
            type="text"
            value={formData.name}
            onChange={e => setFormData({ ...formData, name: e.target.value })}
            placeholder="Rule name"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 8 }}>
            <div>
              <label style={{ fontSize: 11, color: '#9ca3af', display: 'block', marginBottom: 4 }}>Min Score</label>
              <input
                type="number"
                value={formData.conditions.min_score}
                onChange={e => setFormData({ ...formData, conditions: { ...formData.conditions, min_score: parseInt(e.target.value) || 0 } })}
                style={{
                  width: '100%',
                  padding: '6px 8px',
                  borderRadius: 6,
                  border: '1px solid #4b5563',
                  background: '#020617',
                  color: 'white',
                  fontSize: 11,
                }}
              />
            </div>
            <div>
              <label style={{ fontSize: 11, color: '#9ca3af', display: 'block', marginBottom: 4 }}>Min Seen Count</label>
              <input
                type="number"
                value={formData.conditions.min_seen_count}
                onChange={e => setFormData({ ...formData, conditions: { ...formData.conditions, min_seen_count: parseInt(e.target.value) || 0 } })}
                style={{
                  width: '100%',
                  padding: '6px 8px',
                  borderRadius: 6,
                  border: '1px solid #4b5563',
                  background: '#020617',
                  color: 'white',
                  fontSize: 11,
                }}
              />
            </div>
          </div>
          <div style={{ marginBottom: 8 }}>
            <label style={{ fontSize: 11, color: '#9ca3af', display: 'flex', alignItems: 'center', gap: 8 }}>
              <input
                type="checkbox"
                checked={formData.actions.block_ip}
                onChange={e => setFormData({ ...formData, actions: { ...formData.actions, block_ip: e.target.checked } })}
              />
              Auto-block IP
            </label>
            <label style={{ fontSize: 11, color: '#9ca3af', display: 'flex', alignItems: 'center', gap: 8, marginTop: 4 }}>
              <input
                type="checkbox"
                checked={formData.actions.send_email}
                onChange={e => setFormData({ ...formData, actions: { ...formData.actions, send_email: e.target.checked } })}
              />
              Send email
            </label>
          </div>
          {formData.actions.send_email && (
            <input
              type="email"
              value={formData.actions.alert_email}
              onChange={e => setFormData({ ...formData, actions: { ...formData.actions, alert_email: e.target.value } })}
              placeholder="Alert email"
              style={{
                width: '100%',
                padding: '8px 12px',
                borderRadius: 6,
                border: '1px solid #4b5563',
                background: '#020617',
                color: 'white',
                marginBottom: 8,
                fontSize: 12,
              }}
            />
          )}
          <input
            type="text"
            value={formData.actions.webhook_url}
            onChange={e => setFormData({ ...formData, actions: { ...formData.actions, webhook_url: e.target.value } })}
            placeholder="Webhook URL (optional)"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <button
            onClick={handleCreate}
            style={{
              padding: '8px 16px',
              borderRadius: 6,
              border: 'none',
              background: '#22c55e',
              color: '#022c22',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Create Rule
          </button>
        </div>
      )}
      <table className="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Conditions</th>
            <th>Actions</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {rules.length === 0 ? (
            <tr>
              <td colSpan={5} className="muted">
                No alert rules. Create one to automate responses.
              </td>
            </tr>
          ) : (
            rules.map(rule => (
              <tr key={rule.id}>
                <td>{rule.name}</td>
                <td className="muted" style={{ fontSize: 11 }}>
                  Score ≥ {rule.conditions?.min_score || 0}, Seen ≥ {rule.conditions?.min_seen_count || 0}
                </td>
                <td className="muted" style={{ fontSize: 11 }}>
                  {rule.actions?.block_ip && 'Block IP '}
                  {rule.actions?.send_email && 'Email '}
                  {rule.actions?.webhook_url && 'Webhook'}
                </td>
                <td>
                  <span className={`status-pill ${rule.enabled ? '' : 'warn'}`}>
                    {rule.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </td>
                <td>
                  <div style={{ display: 'flex', gap: 4 }}>
                    <button
                      onClick={() => handleToggle(rule.id, rule.enabled)}
                      style={{
                        padding: '4px 8px',
                        fontSize: 10,
                        borderRadius: 4,
                        border: '1px solid #4b5563',
                        background: 'rgba(15, 23, 42, 0.9)',
                        color: '#e5e7eb',
                        cursor: 'pointer',
                      }}
                    >
                      {rule.enabled ? 'Disable' : 'Enable'}
                    </button>
                    <button
                      onClick={() => handleDelete(rule.id)}
                      style={{
                        padding: '4px 8px',
                        fontSize: 10,
                        borderRadius: 4,
                        border: '1px solid #ef4444',
                        background: 'rgba(239, 68, 68, 0.1)',
                        color: '#ef4444',
                        cursor: 'pointer',
                      }}
                    >
                      Delete
                    </button>
                  </div>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </section>
  )
}

function AnalyticsPage() {
  const [trends, setTrends] = useState<any>(null)
  const [patterns, setPatterns] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    loadAnalytics()
    const interval = setInterval(loadAnalytics, 30000)
    return () => clearInterval(interval)
  }, [])

  const loadAnalytics = () => {
    const token = localStorage.getItem('token')
    if (token) {
      setLoading(true)
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      Promise.all([api.get('/api/v1/analytics/trends?days=7'), api.get('/api/v1/analytics/patterns')])
        .then(([trendsRes, patternsRes]) => {
          setTrends(trendsRes.data)
          setPatterns(patternsRes.data)
        })
        .catch(() => {
          setTrends(null)
          setPatterns(null)
        })
        .finally(() => setLoading(false))
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Advanced Analytics</div>
          <div className="page-subtitle">Attack patterns, trends, and anomaly detection.</div>
        </div>
        <button
          onClick={loadAnalytics}
          disabled={loading}
          style={{
            padding: '6px 12px',
            fontSize: 12,
            borderRadius: 6,
            border: '1px solid #4b5563',
            background: 'rgba(15, 23, 42, 0.9)',
            color: '#e5e7eb',
            cursor: loading ? 'not-allowed' : 'pointer',
          }}
        >
          {loading ? 'Loading...' : 'Refresh'}
        </button>
      </div>
      {trends && (
        <div style={{ marginBottom: 24 }}>
          <h3 style={{ fontSize: 14, marginBottom: 12, color: '#e5e7eb' }}>Trends (Last 7 Days)</h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
            <div style={{ padding: 12, background: 'rgba(15, 23, 42, 0.5)', borderRadius: 8 }}>
              <div style={{ fontSize: 11, color: '#9ca3af', marginBottom: 4 }}>Total Events</div>
              <div style={{ fontSize: 24, fontWeight: 600, color: '#e5e7eb' }}>{trends.total_events || 0}</div>
            </div>
            <div style={{ padding: 12, background: 'rgba(15, 23, 42, 0.5)', borderRadius: 8 }}>
              <div style={{ fontSize: 11, color: '#9ca3af', marginBottom: 4 }}>Total IOCs</div>
              <div style={{ fontSize: 24, fontWeight: 600, color: '#e5e7eb' }}>{trends.total_iocs || 0}</div>
            </div>
            <div style={{ padding: 12, background: 'rgba(15, 23, 42, 0.5)', borderRadius: 8 }}>
              <div style={{ fontSize: 11, color: '#9ca3af', marginBottom: 4 }}>High Risk IOCs</div>
              <div style={{ fontSize: 24, fontWeight: 600, color: '#ef4444' }}>{trends.high_risk_iocs_count || 0}</div>
            </div>
            <div style={{ padding: 12, background: 'rgba(15, 23, 42, 0.5)', borderRadius: 8 }}>
              <div style={{ fontSize: 11, color: '#9ca3af', marginBottom: 4 }}>Anomalies</div>
              <div style={{ fontSize: 24, fontWeight: 600, color: '#f59e0b' }}>{trends.anomalies?.length || 0}</div>
            </div>
          </div>
        </div>
      )}
      {patterns && (
        <div>
          <h3 style={{ fontSize: 14, marginBottom: 12, color: '#e5e7eb' }}>Attack Patterns</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div>
              <h4 style={{ fontSize: 12, marginBottom: 8, color: '#9ca3af' }}>Dangerous Commands</h4>
              <table className="table">
                <thead>
                  <tr>
                    <th>Command</th>
                    <th>Count</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(patterns.dangerous_commands || {}).slice(0, 5).map(([cmd, count]: [string, any]) => (
                    <tr key={cmd}>
                      <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{cmd}</td>
                      <td>{count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div>
              <h4 style={{ fontSize: 12, marginBottom: 8, color: '#9ca3af' }}>Targeted Paths</h4>
              <table className="table">
                <thead>
                  <tr>
                    <th>Path</th>
                    <th>Count</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(patterns.targeted_paths || {}).slice(0, 5).map(([path, count]: [string, any]) => (
                    <tr key={path}>
                      <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{path}</td>
                      <td>{count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}

function UsersPage() {
  const [users, setUsers] = useState<any[]>([])
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({ email: '', password: '', role: 'viewer' })

  useEffect(() => {
    loadUsers()
  }, [])

  const loadUsers = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api
        .get('/api/v1/users')
        .then(res => setUsers(Array.isArray(res.data) ? res.data : []))
        .catch(() => setUsers([]))
    }
  }

  const handleCreate = async () => {
    try {
      await api.post('/api/v1/users', formData)
      setFormData({ email: '', password: '', role: 'viewer' })
      setShowForm(false)
      loadUsers()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create user')
    }
  }

  const handleRoleChange = async (userId: number, newRole: string) => {
    try {
      await api.put(`/api/v1/users/${userId}/role`, null, { params: { role: newRole } })
      loadUsers()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to update role')
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">User Management</div>
          <div className="page-subtitle">Manage users and their roles.</div>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          style={{
            padding: '6px 12px',
            borderRadius: 8,
            border: '1px solid #22c55e',
            background: 'rgba(34, 197, 94, 0.1)',
            color: '#22c55e',
            cursor: 'pointer',
            fontSize: 12,
          }}
        >
          {showForm ? 'Cancel' : '+ Add User'}
        </button>
      </div>
      {showForm && (
        <div style={{ marginBottom: 16, padding: 16, border: '1px solid #374151', borderRadius: 8 }}>
          <input
            type="email"
            value={formData.email}
            onChange={e => setFormData({ ...formData, email: e.target.value })}
            placeholder="Email"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <input
            type="password"
            value={formData.password}
            onChange={e => setFormData({ ...formData, password: e.target.value })}
            placeholder="Password"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <select
            value={formData.role}
            onChange={e => setFormData({ ...formData, role: e.target.value })}
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          >
            <option value="admin">Admin</option>
            <option value="operator">Operator</option>
            <option value="viewer">Viewer</option>
          </select>
          <button
            onClick={handleCreate}
            style={{
              padding: '8px 16px',
              borderRadius: 6,
              border: 'none',
              background: '#22c55e',
              color: '#022c22',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Create User
          </button>
        </div>
      )}
      <table className="table">
        <thead>
          <tr>
            <th>Email</th>
            <th>Role</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {users.length === 0 ? (
            <tr>
              <td colSpan={3} className="muted">
                No users found.
              </td>
            </tr>
          ) : (
            users.map(user => (
              <tr key={user.id}>
                <td>{user.email}</td>
                <td>
                  <select
                    value={user.role}
                    onChange={e => handleRoleChange(user.id, e.target.value)}
                    style={{
                      padding: '4px 8px',
                      borderRadius: 4,
                      border: '1px solid #4b5563',
                      background: '#020617',
                      color: 'white',
                      fontSize: 11,
                    }}
                  >
                    <option value="admin">Admin</option>
                    <option value="operator">Operator</option>
                    <option value="viewer">Viewer</option>
                  </select>
                </td>
                <td>
                  <span className="chip">{user.role}</span>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </section>
  )
}

function TemplatesPage() {
  const [templates, setTemplates] = useState<any[]>([])
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({ name: '', type: 'ssh', default_config: '{}' })

  useEffect(() => {
    loadTemplates()
    const interval = setInterval(loadTemplates, 5000)
    return () => clearInterval(interval)
  }, [])

  const loadTemplates = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api
        .get('/api/v1/templates')
        .then(res => setTemplates(Array.isArray(res.data) ? res.data : []))
        .catch(() => setTemplates([]))
    }
  }

  const handleCreate = async () => {
    try {
      const config = JSON.parse(formData.default_config)
      await api.post('/api/v1/templates', { name: formData.name, type: formData.type, default_config: config })
      setFormData({ name: '', type: 'ssh', default_config: '{}' })
      setShowForm(false)
      loadTemplates()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create template')
    }
  }

  const handleDelete = async (templateId: number) => {
    if (!confirm('Delete this template?')) return
    try {
      await api.delete(`/api/v1/templates/${templateId}`)
      loadTemplates()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to delete template')
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Honeypot Templates</div>
          <div className="page-subtitle">Manage honeypot configuration templates.</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={loadTemplates}
            style={{
              padding: '6px 12px',
              borderRadius: 8,
              border: '1px solid #4b5563',
              background: 'rgba(15, 23, 42, 0.9)',
              color: '#e5e7eb',
              cursor: 'pointer',
              fontSize: 12,
            }}
          >
            🔄 Refresh
          </button>
          <button
            onClick={() => setShowForm(!showForm)}
            style={{
              padding: '6px 12px',
              borderRadius: 8,
              border: '1px solid #22c55e',
              background: 'rgba(34, 197, 94, 0.1)',
              color: '#22c55e',
              cursor: 'pointer',
              fontSize: 12,
            }}
          >
            {showForm ? 'Cancel' : '+ Create Template'}
          </button>
        </div>
      </div>
      {showForm && (
        <div style={{ marginBottom: 16, padding: 16, border: '1px solid #374151', borderRadius: 8 }}>
          <input
            type="text"
            value={formData.name}
            onChange={e => setFormData({ ...formData, name: e.target.value })}
            placeholder="Template name"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <select
            value={formData.type}
            onChange={e => setFormData({ ...formData, type: e.target.value })}
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          >
            <option value="ssh">SSH</option>
            <option value="web">Web</option>
            <option value="db">Database</option>
            <option value="ics">ICS</option>
          </select>
          <textarea
            value={formData.default_config}
            onChange={e => setFormData({ ...formData, default_config: e.target.value })}
            placeholder='JSON config, e.g. {"banner": "SSH-2.0-OpenSSH_7.4"}'
            rows={4}
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 11,
              fontFamily: 'monospace',
            }}
          />
          <button
            onClick={handleCreate}
            style={{
              padding: '8px 16px',
              borderRadius: 6,
              border: 'none',
              background: '#22c55e',
              color: '#022c22',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Create Template
          </button>
        </div>
      )}
      <table className="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Config</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {templates.length === 0 ? (
            <tr>
              <td colSpan={4} className="muted">
                No templates.
              </td>
            </tr>
          ) : (
            templates.map(template => (
              <tr key={template.id}>
                <td>{template.name}</td>
                <td>
                  <span className="chip">{template.type}</span>
                </td>
                <td className="muted" style={{ fontSize: 11, fontFamily: 'monospace' }}>
                  {JSON.stringify(template.default_config).substring(0, 50)}
                </td>
                <td>
                  <button
                    onClick={() => handleDelete(template.id)}
                    style={{
                      padding: '4px 8px',
                      fontSize: 10,
                      borderRadius: 4,
                      border: '1px solid #ef4444',
                      background: 'rgba(239, 68, 68, 0.1)',
                      color: '#ef4444',
                      cursor: 'pointer',
                    }}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </section>
  )
}

function BackupsPage() {
  const [backups, setBackups] = useState<any[]>([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    loadBackups()
  }, [])

  const loadBackups = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api
        .get('/api/v1/backups')
        .then(res => setBackups(Array.isArray(res.data) ? res.data : []))
        .catch(() => setBackups([]))
    }
  }

  const handleCreate = async (backupType: string) => {
    setLoading(true)
    try {
      const res = await api.post('/api/v1/backup/create', null, { params: { backup_type: backupType } })
      const blob = new Blob([JSON.stringify(res.data.data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = res.data.filename
      a.click()
      loadBackups()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create backup')
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Backups</div>
          <div className="page-subtitle">Create and manage database backups.</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={() => handleCreate('full')}
            disabled={loading}
            style={{
              padding: '6px 12px',
              borderRadius: 8,
              border: 'none',
              background: '#22c55e',
              color: '#022c22',
              fontSize: 12,
              fontWeight: 600,
              cursor: loading ? 'not-allowed' : 'pointer',
            }}
          >
            {loading ? 'Creating...' : 'Full Backup'}
          </button>
          <button
            onClick={() => handleCreate('events')}
            disabled={loading}
            style={{
              padding: '6px 12px',
              borderRadius: 8,
              border: '1px solid #4b5563',
              background: 'rgba(15, 23, 42, 0.9)',
              color: '#e5e7eb',
              fontSize: 12,
              cursor: loading ? 'not-allowed' : 'pointer',
            }}
          >
            Events Only
          </button>
        </div>
      </div>
      <table className="table">
        <thead>
          <tr>
            <th>Filename</th>
            <th>Type</th>
            <th>Size</th>
            <th>Created</th>
          </tr>
        </thead>
        <tbody>
          {backups.length === 0 ? (
            <tr>
              <td colSpan={4} className="muted">
                No backups created yet.
              </td>
            </tr>
          ) : (
            backups.map(backup => (
              <tr key={backup.id}>
                <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{backup.filename}</td>
                <td>
                  <span className="chip">{backup.backup_type}</span>
                </td>
                <td className="muted" style={{ fontSize: 11 }}>
                  {(backup.size_bytes / 1024).toFixed(2)} KB
                </td>
                <td className="muted" style={{ fontSize: 11 }}>
                  {new Date(backup.created_at).toLocaleString()}
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </section>
  )
}

function IncidentsPage() {
  const [incidents, setIncidents] = useState<any[]>([])
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({ title: '', description: '', severity: 'medium' })

  useEffect(() => {
    loadIncidents()
    const interval = setInterval(loadIncidents, 10000)
    return () => clearInterval(interval)
  }, [])

  const loadIncidents = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api.get('/api/v1/incidents').then(res => setIncidents(Array.isArray(res.data) ? res.data : [])).catch(() => setIncidents([]))
    }
  }

  const handleCreate = async () => {
    try {
      await api.post('/api/v1/incidents', formData)
      setFormData({ title: '', description: '', severity: 'medium' })
      setShowForm(false)
      loadIncidents()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create incident')
    }
  }

  const handleStatusChange = async (incidentId: number, newStatus: string) => {
    try {
      await api.put(`/api/v1/incidents/${incidentId}`, null, { params: { status: newStatus } })
      loadIncidents()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to update incident')
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Incidents</div>
          <div className="page-subtitle">Manage security incidents and cases.</div>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          style={{
            padding: '6px 12px',
            borderRadius: 8,
            border: '1px solid #22c55e',
            background: 'rgba(34, 197, 94, 0.1)',
            color: '#22c55e',
            cursor: 'pointer',
            fontSize: 12,
          }}
        >
          {showForm ? 'Cancel' : '+ Create Incident'}
        </button>
      </div>
      {showForm && (
        <div style={{ marginBottom: 16, padding: 16, border: '1px solid #374151', borderRadius: 8 }}>
          <input
            type="text"
            value={formData.title}
            onChange={e => setFormData({ ...formData, title: e.target.value })}
            placeholder="Incident title"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <textarea
            value={formData.description}
            onChange={e => setFormData({ ...formData, description: e.target.value })}
            placeholder="Description"
            rows={3}
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <select
            value={formData.severity}
            onChange={e => setFormData({ ...formData, severity: e.target.value })}
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          >
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
          <button
            onClick={handleCreate}
            style={{
              padding: '8px 16px',
              borderRadius: 6,
              border: 'none',
              background: '#22c55e',
              color: '#022c22',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Create Incident
          </button>
        </div>
      )}
      <table className="table">
        <thead>
          <tr>
            <th>Title</th>
            <th>Severity</th>
            <th>Status</th>
            <th>Created</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {incidents.length === 0 ? (
            <tr>
              <td colSpan={5} className="muted">
                No incidents. Create one to track security events.
              </td>
            </tr>
          ) : (
            incidents.map(incident => (
              <tr key={incident.id}>
                <td>{incident.title}</td>
                <td>
                  <span className={`status-pill ${incident.severity === 'critical' ? 'error' : incident.severity === 'high' ? 'warn' : ''}`}>
                    {incident.severity}
                  </span>
                </td>
                <td>
                  <select
                    value={incident.status}
                    onChange={e => handleStatusChange(incident.id, e.target.value)}
                    style={{
                      padding: '4px 8px',
                      borderRadius: 4,
                      border: '1px solid #4b5563',
                      background: '#020617',
                      color: 'white',
                      fontSize: 11,
                    }}
                  >
                    <option value="open">Open</option>
                    <option value="investigating">Investigating</option>
                    <option value="contained">Contained</option>
                    <option value="closed">Closed</option>
                  </select>
                </td>
                <td className="muted" style={{ fontSize: 11 }}>
                  {new Date(incident.created_at).toLocaleString()}
                </td>
                <td>
                  <button
                    onClick={() => window.location.href = `/incidents/${incident.id}`}
                    style={{
                      padding: '4px 8px',
                      fontSize: 10,
                      borderRadius: 4,
                      border: '1px solid #4b5563',
                      background: 'rgba(15, 23, 42, 0.9)',
                      color: '#e5e7eb',
                      cursor: 'pointer',
                    }}
                  >
                    View
                  </button>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </section>
  )
}

function MITREPage() {
  const [stats, setStats] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    loadStats()
    const interval = setInterval(loadStats, 30000)
    return () => clearInterval(interval)
  }, [])

  const loadStats = () => {
    const token = localStorage.getItem('token')
    if (token) {
      setLoading(true)
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api.get('/api/v1/mitre/statistics?days=30')
        .then(res => setStats(res.data))
        .catch(() => setStats(null))
        .finally(() => setLoading(false))
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">MITRE ATT&CK</div>
          <div className="page-subtitle">Attack technique mapping and statistics.</div>
        </div>
        <button
          onClick={loadStats}
          disabled={loading}
          style={{
            padding: '6px 12px',
            fontSize: 12,
            borderRadius: 6,
            border: '1px solid #4b5563',
            background: 'rgba(15, 23, 42, 0.9)',
            color: '#e5e7eb',
            cursor: loading ? 'not-allowed' : 'pointer',
          }}
        >
          {loading ? 'Loading...' : 'Refresh'}
        </button>
      </div>
      {stats && (
        <div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12, marginBottom: 24 }}>
            <div style={{ padding: 12, background: 'rgba(15, 23, 42, 0.5)', borderRadius: 8 }}>
              <div style={{ fontSize: 11, color: '#9ca3af', marginBottom: 4 }}>Total Events</div>
              <div style={{ fontSize: 24, fontWeight: 600, color: '#e5e7eb' }}>{stats.total_events || 0}</div>
            </div>
            <div style={{ padding: 12, background: 'rgba(15, 23, 42, 0.5)', borderRadius: 8 }}>
              <div style={{ fontSize: 11, color: '#9ca3af', marginBottom: 4 }}>Techniques</div>
              <div style={{ fontSize: 24, fontWeight: 600, color: '#e5e7eb' }}>{Object.keys(stats.techniques || {}).length}</div>
            </div>
            <div style={{ padding: 12, background: 'rgba(15, 23, 42, 0.5)', borderRadius: 8 }}>
              <div style={{ fontSize: 11, color: '#9ca3af', marginBottom: 4 }}>Tactics</div>
              <div style={{ fontSize: 24, fontWeight: 600, color: '#e5e7eb' }}>{Object.keys(stats.tactics || {}).length}</div>
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div>
              <h3 style={{ fontSize: 14, marginBottom: 12, color: '#e5e7eb' }}>Techniques</h3>
              <table className="table">
                <thead>
                  <tr>
                    <th>Technique ID</th>
                    <th>Count</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(stats.techniques || {}).slice(0, 10).map(([tech, count]: [string, any]) => (
                    <tr key={tech}>
                      <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{tech}</td>
                      <td>{count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div>
              <h3 style={{ fontSize: 14, marginBottom: 12, color: '#e5e7eb' }}>Tactics</h3>
              <table className="table">
                <thead>
                  <tr>
                    <th>Tactic</th>
                    <th>Count</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(stats.tactics || {}).map(([tactic, count]: [string, any]) => (
                    <tr key={tactic}>
                      <td>{tactic}</td>
                      <td>{count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}

function PlaybooksPage() {
  const [playbooks, setPlaybooks] = useState<any[]>([])
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({ name: '', description: '', enabled: true, trigger_conditions: '{}', steps: '[]' })

  useEffect(() => {
    loadPlaybooks()
  }, [])

  const loadPlaybooks = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api.get('/api/v1/playbooks').then(res => setPlaybooks(Array.isArray(res.data) ? res.data : [])).catch(() => setPlaybooks([]))
    }
  }

  const handleCreate = async () => {
    try {
      const conditions = JSON.parse(formData.trigger_conditions)
      const steps = JSON.parse(formData.steps)
      await api.post('/api/v1/playbooks', {
        name: formData.name,
        description: formData.description,
        trigger_conditions: conditions,
        steps,
        enabled: formData.enabled,
      })
      setFormData({ name: '', description: '', enabled: true, trigger_conditions: '{}', steps: '[]' })
      setShowForm(false)
      loadPlaybooks()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create playbook')
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Playbooks</div>
          <div className="page-subtitle">Automated response playbooks for security events.</div>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          style={{
            padding: '6px 12px',
            borderRadius: 8,
            border: '1px solid #22c55e',
            background: 'rgba(34, 197, 94, 0.1)',
            color: '#22c55e',
            cursor: 'pointer',
            fontSize: 12,
          }}
        >
          {showForm ? 'Cancel' : '+ Create Playbook'}
        </button>
      </div>
      {showForm && (
        <div style={{ marginBottom: 16, padding: 16, border: '1px solid #374151', borderRadius: 8 }}>
          <input
            type="text"
            value={formData.name}
            onChange={e => setFormData({ ...formData, name: e.target.value })}
            placeholder="Playbook name"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <textarea
            value={formData.description}
            onChange={e => setFormData({ ...formData, description: e.target.value })}
            placeholder="Description"
            rows={2}
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <textarea
            value={formData.trigger_conditions}
            onChange={e => setFormData({ ...formData, trigger_conditions: e.target.value })}
            placeholder='Trigger conditions JSON, e.g. {"event_type": "ssh_connection", "min_score": 70}'
            rows={2}
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 11,
              fontFamily: 'monospace',
            }}
          />
          <textarea
            value={formData.steps}
            onChange={e => setFormData({ ...formData, steps: e.target.value })}
            placeholder='Steps JSON, e.g. [{"action": "whois", "target": "src_ip"}, {"action": "block_ip"}]'
            rows={3}
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 11,
              fontFamily: 'monospace',
            }}
          />
          <button
            onClick={handleCreate}
            style={{
              padding: '8px 16px',
              borderRadius: 6,
              border: 'none',
              background: '#22c55e',
              color: '#022c22',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Create Playbook
          </button>
        </div>
      )}
      <table className="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Description</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {playbooks.length === 0 ? (
            <tr>
              <td colSpan={4} className="muted">
                No playbooks. Create one to automate responses.
              </td>
            </tr>
          ) : (
            playbooks.map(playbook => (
              <tr key={playbook.id}>
                <td>{playbook.name}</td>
                <td className="muted" style={{ fontSize: 11 }}>
                  {playbook.description || '-'}
                </td>
                <td>
                  <span className={`status-pill ${playbook.enabled ? '' : 'warn'}`}>
                    {playbook.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </td>
                <td>
                  <button
                    onClick={() => window.location.href = `/playbooks/${playbook.id}`}
                    style={{
                      padding: '4px 8px',
                      fontSize: 10,
                      borderRadius: 4,
                      border: '1px solid #4b5563',
                      background: 'rgba(15, 23, 42, 0.9)',
                      color: '#e5e7eb',
                      cursor: 'pointer',
                    }}
                  >
                    View
                  </button>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </section>
  )
}

function CampaignsPage() {
  const [campaigns, setCampaigns] = useState<any[]>([])
  const [honeypots, setHoneypots] = useState<any[]>([])
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({ name: '', description: '', target_network: '', honeypot_ids: [] as number[] })

  useEffect(() => {
    loadCampaigns()
    loadHoneypots()
    const interval = setInterval(() => {
      loadCampaigns()
    }, 10000)
    return () => clearInterval(interval)
  }, [])

  const loadCampaigns = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api.get('/api/v1/campaigns').then(res => setCampaigns(Array.isArray(res.data) ? res.data : [])).catch(() => setCampaigns([]))
    }
  }

  const loadHoneypots = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api.get('/api/v1/honeypots').then(res => setHoneypots(Array.isArray(res.data) ? res.data : [])).catch(() => setHoneypots([]))
    }
  }

  const handleCreate = async () => {
    try {
      await api.post('/api/v1/campaigns', {
        name: formData.name,
        description: formData.description,
        target_network: formData.target_network,
        honeypot_ids: formData.honeypot_ids,
      })
      setFormData({ name: '', description: '', target_network: '', honeypot_ids: [] })
      setShowForm(false)
      loadCampaigns()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create campaign')
    }
  }

  const handleStart = async (campaignId: number) => {
    try {
      await api.post(`/api/v1/campaigns/${campaignId}/start`)
      loadCampaigns()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to start campaign')
    }
  }

  const handleStop = async (campaignId: number) => {
    try {
      await api.post(`/api/v1/campaigns/${campaignId}/stop`)
      loadCampaigns()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to stop campaign')
    }
  }

  const handleDelete = async (campaignId: number) => {
    if (!confirm('Delete this campaign?')) return
    try {
      await api.delete(`/api/v1/campaigns/${campaignId}`)
      loadCampaigns()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to delete campaign')
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Deception Campaigns</div>
          <div className="page-subtitle">Organize honeypots into targeted deception campaigns.</div>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          style={{
            padding: '6px 12px',
            borderRadius: 8,
            border: '1px solid #22c55e',
            background: 'rgba(34, 197, 94, 0.1)',
            color: '#22c55e',
            cursor: 'pointer',
            fontSize: 12,
          }}
        >
          {showForm ? 'Cancel' : '+ Create Campaign'}
        </button>
      </div>
      {showForm && (
        <div style={{ marginBottom: 16, padding: 16, border: '1px solid #374151', borderRadius: 8 }}>
          <input
            type="text"
            value={formData.name}
            onChange={e => setFormData({ ...formData, name: e.target.value })}
            placeholder="Campaign name"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <textarea
            value={formData.description}
            onChange={e => setFormData({ ...formData, description: e.target.value })}
            placeholder="Description"
            rows={2}
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <select
            value={formData.target_network}
            onChange={e => setFormData({ ...formData, target_network: e.target.value })}
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          >
            <option value="">Select Target Network</option>
            <option value="DMZ">DMZ</option>
            <option value="Internal">Internal</option>
            <option value="External">External</option>
            <option value="Cloud">Cloud</option>
          </select>
          <div style={{ marginBottom: 8 }}>
            <label style={{ fontSize: 11, color: '#9ca3af', display: 'block', marginBottom: 4 }}>Select Honeypots</label>
            <div style={{ maxHeight: 150, overflowY: 'auto', border: '1px solid #4b5563', borderRadius: 6, padding: 8 }}>
              {honeypots.map(hp => (
                <label key={hp.id} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, fontSize: 11 }}>
                  <input
                    type="checkbox"
                    checked={formData.honeypot_ids.includes(hp.id)}
                    onChange={e => {
                      if (e.target.checked) {
                        setFormData({ ...formData, honeypot_ids: [...formData.honeypot_ids, hp.id] })
                      } else {
                        setFormData({ ...formData, honeypot_ids: formData.honeypot_ids.filter(id => id !== hp.id) })
                      }
                    }}
                  />
                  {hp.name} ({hp.status})
                </label>
              ))}
            </div>
          </div>
          <button
            onClick={handleCreate}
            style={{
              padding: '8px 16px',
              borderRadius: 6,
              border: 'none',
              background: '#22c55e',
              color: '#022c22',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Create Campaign
          </button>
        </div>
      )}
      <table className="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Target Network</th>
            <th>Status</th>
            <th>Created</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {campaigns.length === 0 ? (
            <tr>
              <td colSpan={5} className="muted">
                No campaigns. Create one to organize your honeypots.
              </td>
            </tr>
          ) : (
            campaigns.map(campaign => (
              <tr key={campaign.id}>
                <td>
                  <div>
                    <div style={{ fontWeight: 600 }}>{campaign.name}</div>
                    {campaign.description && (
                      <div className="muted" style={{ fontSize: 11, marginTop: 2 }}>
                        {campaign.description}
                      </div>
                    )}
                  </div>
                </td>
                <td>
                  <span className="chip">{campaign.target_network || 'N/A'}</span>
                </td>
                <td>
                  <span className={`status-pill ${campaign.status === 'active' ? '' : campaign.status === 'paused' ? 'warn' : ''}`}>
                    {campaign.status}
                  </span>
                </td>
                <td className="muted" style={{ fontSize: 11 }}>
                  {new Date(campaign.created_at).toLocaleString()}
                </td>
                <td>
                  <div style={{ display: 'flex', gap: 4 }}>
                    {campaign.status === 'draft' || campaign.status === 'paused' ? (
                      <button
                        onClick={() => handleStart(campaign.id)}
                        style={{
                          padding: '4px 8px',
                          fontSize: 10,
                          borderRadius: 4,
                          border: '1px solid #22c55e',
                          background: 'rgba(34, 197, 94, 0.1)',
                          color: '#22c55e',
                          cursor: 'pointer',
                        }}
                      >
                        Start
                      </button>
                    ) : (
                      <button
                        onClick={() => handleStop(campaign.id)}
                        style={{
                          padding: '4px 8px',
                          fontSize: 10,
                          borderRadius: 4,
                          border: '1px solid #f59e0b',
                          background: 'rgba(245, 158, 11, 0.1)',
                          color: '#f59e0b',
                          cursor: 'pointer',
                        }}
                      >
                        Stop
                      </button>
                    )}
                    <button
                      onClick={() => window.location.href = `/campaigns/${campaign.id}`}
                      style={{
                        padding: '4px 8px',
                        fontSize: 10,
                        borderRadius: 4,
                        border: '1px solid #4b5563',
                        background: 'rgba(15, 23, 42, 0.9)',
                        color: '#e5e7eb',
                        cursor: 'pointer',
                      }}
                    >
                      View
                    </button>
                    <button
                      onClick={() => handleDelete(campaign.id)}
                      style={{
                        padding: '4px 8px',
                        fontSize: 10,
                        borderRadius: 4,
                        border: '1px solid #ef4444',
                        background: 'rgba(239, 68, 68, 0.1)',
                        color: '#ef4444',
                        cursor: 'pointer',
                      }}
                    >
                      Delete
                    </button>
                  </div>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </section>
  )
}

function AttackReplayPage() {
  const [sessions, setSessions] = useState<any[]>([])
  const [selectedSession, setSelectedSession] = useState<number | null>(null)
  const [replayData, setReplayData] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    loadSessions()
    const interval = setInterval(loadSessions, 10000)
    return () => clearInterval(interval)
  }, [])

  const loadSessions = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api.get('/api/v1/sessions?limit=50').then(res => setSessions(Array.isArray(res.data) ? res.data : [])).catch(() => setSessions([]))
    }
  }

  const loadReplay = async (sessionId: number) => {
    setLoading(true)
    try {
      const res = await api.get(`/api/v1/sessions/${sessionId}/replay`)
      setReplayData(res.data)
      setSelectedSession(sessionId)
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to load replay')
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Attack Replay</div>
          <div className="page-subtitle">Replay attacker sessions with timeline visualization.</div>
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: 16 }}>
        <div style={{ border: '1px solid #374151', borderRadius: 8, padding: 16, maxHeight: '80vh', overflowY: 'auto' }}>
          <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 12 }}>Sessions</div>
          {sessions.length === 0 ? (
            <div className="muted" style={{ fontSize: 11 }}>No sessions yet</div>
          ) : (
            sessions.map(session => (
              <div
                key={session.id}
                onClick={() => loadReplay(session.id)}
                style={{
                  padding: 8,
                  marginBottom: 4,
                  borderRadius: 6,
                  background: selectedSession === session.id ? 'rgba(34, 197, 94, 0.2)' : 'rgba(15, 23, 42, 0.9)',
                  border: '1px solid #374151',
                  cursor: 'pointer',
                  fontSize: 11,
                }}
              >
                <div style={{ fontFamily: 'monospace', fontWeight: 600 }}>{session.src_ip}</div>
                <div className="muted" style={{ fontSize: 10, marginTop: 2 }}>
                  {new Date(session.started_at).toLocaleString()}
                </div>
              </div>
            ))
          )}
        </div>
        <div style={{ border: '1px solid #374151', borderRadius: 8, padding: 16 }}>
          {loading ? (
            <div className="muted">Loading replay...</div>
          ) : replayData ? (
            <>
              <div style={{ marginBottom: 16 }}>
                <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 4 }}>Session Replay</div>
                <div style={{ fontSize: 11, color: '#9ca3af' }}>
                  IP: <span style={{ fontFamily: 'monospace' }}>{replayData.src_ip}</span> | 
                  Events: {replayData.total_events} | 
                  Type: {replayData.honeypot_type}
                </div>
              </div>
              <div style={{ maxHeight: '70vh', overflowY: 'auto' }}>
                {replayData.timeline.map((item: any, idx: number) => (
                  <div
                    key={idx}
                    style={{
                      padding: 12,
                      marginBottom: 8,
                      background: 'rgba(15, 23, 42, 0.9)',
                      border: '1px solid #374151',
                      borderRadius: 6,
                      borderLeft: '3px solid #22c55e',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                      <span style={{ fontSize: 11, fontWeight: 600 }}>#{item.index}</span>
                      <span className="muted" style={{ fontSize: 10 }}>
                        {new Date(item.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                    <div style={{ fontSize: 12, marginBottom: 4 }}>
                      <span className="chip" style={{ fontSize: 10 }}>{item.event_type}</span>
                    </div>
                    <div style={{ fontSize: 11, color: '#e5e7eb' }}>
                      {item.action || JSON.stringify(item.payload).substring(0, 100)}
                    </div>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="muted" style={{ textAlign: 'center', padding: 40 }}>
              Select a session to view replay
            </div>
          )}
        </div>
      </div>
    </section>
  )
}

function DetectionLabPage() {
  const [scenarios, setScenarios] = useState<any[]>([])
  const [sessions, setSessions] = useState<any[]>([])
  const [selectedScenario, setSelectedScenario] = useState<number | null>(null)
  const [checkResults, setCheckResults] = useState<any>({})

  useEffect(() => {
    loadScenarios()
    loadSessions()
  }, [])

  const loadScenarios = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api.get('/api/v1/detection-lab/scenarios').then(res => setScenarios(Array.isArray(res.data) ? res.data : [])).catch(() => setScenarios([]))
    }
  }

  const loadSessions = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api.get('/api/v1/sessions?limit=100').then(res => setSessions(Array.isArray(res.data) ? res.data : [])).catch(() => setSessions([]))
    }
  }

  const checkScenario = async (scenarioId: number, sessionId: number) => {
    try {
      const res = await api.post(`/api/v1/detection-lab/scenarios/${scenarioId}/check`, null, {
        params: { session_id: sessionId },
      })
      setCheckResults({ ...checkResults, [`${scenarioId}-${sessionId}`]: res.data })
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to check scenario')
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Detection Lab</div>
          <div className="page-subtitle">Test your detection capabilities with pre-defined attack scenarios.</div>
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div style={{ border: '1px solid #374151', borderRadius: 8, padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 12 }}>Scenarios</div>
          {scenarios.length === 0 ? (
            <div className="muted" style={{ fontSize: 11 }}>No scenarios available</div>
          ) : (
            scenarios.map(scenario => (
              <div
                key={scenario.id}
                style={{
                  padding: 12,
                  marginBottom: 8,
                  background: 'rgba(15, 23, 42, 0.9)',
                  border: '1px solid #374151',
                  borderRadius: 6,
                }}
              >
                <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 4 }}>{scenario.name}</div>
                <div className="muted" style={{ fontSize: 11, marginBottom: 8 }}>{scenario.description}</div>
                <div style={{ fontSize: 10 }}>
                  <span className="chip">{scenario.scenario_type}</span>
                </div>
              </div>
            ))
          )}
        </div>
        <div style={{ border: '1px solid #374151', borderRadius: 8, padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 12 }}>Test Sessions</div>
          {sessions.length === 0 ? (
            <div className="muted" style={{ fontSize: 11 }}>No sessions available</div>
          ) : (
            sessions.map(session => (
              <div
                key={session.id}
                style={{
                  padding: 12,
                  marginBottom: 8,
                  background: 'rgba(15, 23, 42, 0.9)',
                  border: '1px solid #374151',
                  borderRadius: 6,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                  <div>
                    <div style={{ fontFamily: 'monospace', fontSize: 11, fontWeight: 600 }}>{session.src_ip}</div>
                    <div className="muted" style={{ fontSize: 10 }}>
                      {new Date(session.started_at).toLocaleString()}
                    </div>
                  </div>
                  <button
                    onClick={() => {
                      if (selectedScenario) {
                        checkScenario(selectedScenario, session.id)
                      } else {
                        alert('Please select a scenario first')
                      }
                    }}
                    style={{
                      padding: '4px 8px',
                      fontSize: 10,
                      borderRadius: 4,
                      border: '1px solid #22c55e',
                      background: 'rgba(34, 197, 94, 0.1)',
                      color: '#22c55e',
                      cursor: 'pointer',
                    }}
                  >
                    Test
                  </button>
                </div>
                {checkResults[`${selectedScenario}-${session.id}`] && (
                  <div
                    style={{
                      padding: 8,
                      marginTop: 8,
                      background: checkResults[`${selectedScenario}-${session.id}`].matched
                        ? 'rgba(34, 197, 94, 0.1)'
                        : 'rgba(239, 68, 68, 0.1)',
                      border: `1px solid ${checkResults[`${selectedScenario}-${session.id}`].matched ? '#22c55e' : '#ef4444'}`,
                      borderRadius: 4,
                      fontSize: 10,
                    }}
                  >
                    {checkResults[`${selectedScenario}-${session.id}`].matched ? '✓ Matched' : '✗ Not Matched'}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </section>
  )
}

function MLAnomalyPage() {
  const [selectedIP, setSelectedIP] = useState('')
  const [anomalyData, setAnomalyData] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  const checkAnomaly = async () => {
    if (!selectedIP) {
      alert('Please enter an IP address')
      return
    }
    setLoading(true)
    try {
      const res = await api.get(`/api/v1/ml-anomaly/${selectedIP}`)
      setAnomalyData(res.data)
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to check anomaly')
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">ML Anomaly Detection</div>
          <div className="page-subtitle">Machine learning-based anomaly detection and attack chain analysis.</div>
        </div>
      </div>
      <div style={{ marginBottom: 16 }}>
        <input
          type="text"
          value={selectedIP}
          onChange={e => setSelectedIP(e.target.value)}
          placeholder="Enter IP address"
          style={{
            width: '300px',
            padding: '8px 12px',
            borderRadius: 6,
            border: '1px solid #4b5563',
            background: '#020617',
            color: 'white',
            marginRight: 8,
            fontSize: 12,
          }}
        />
        <button
          onClick={checkAnomaly}
          disabled={loading}
          style={{
            padding: '8px 16px',
            borderRadius: 6,
            border: 'none',
            background: '#22c55e',
            color: '#022c22',
            fontSize: 12,
            fontWeight: 600,
            cursor: loading ? 'not-allowed' : 'pointer',
          }}
        >
          {loading ? 'Checking...' : 'Check Anomaly'}
        </button>
      </div>
      {anomalyData && (
        <div>
          <div style={{ marginBottom: 16, padding: 16, background: 'rgba(15, 23, 42, 0.9)', borderRadius: 8, border: '1px solid #374151' }}>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>Anomaly Detection Results</div>
            <div style={{ fontSize: 12 }}>
              <div>Anomaly Detected: <span style={{ color: anomalyData.anomaly?.anomaly ? '#ef4444' : '#22c55e' }}>{anomalyData.anomaly?.anomaly ? 'Yes' : 'No'}</span></div>
              <div>Anomaly Score: {anomalyData.anomaly?.score?.toFixed(2) || 0}</div>
              {anomalyData.attack_chain?.chain_detected && (
                <div style={{ marginTop: 8, padding: 8, background: 'rgba(239, 68, 68, 0.1)', borderRadius: 4 }}>
                  <div style={{ fontWeight: 600, color: '#ef4444' }}>Attack Chain Detected!</div>
                  <div>Stages: {anomalyData.attack_chain.stages?.join(', ')}</div>
                  <div>Severity: {anomalyData.attack_chain.severity}</div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </section>
  )
}

function ThreatIntelPage() {
  const [feeds, setFeeds] = useState<any[]>([])
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({ name: '', source: 'abuseipdb', api_key: '', enabled: true })

  useEffect(() => {
    loadFeeds()
  }, [])

  const loadFeeds = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api.get('/api/v1/threat-intel/feeds').then(res => setFeeds(Array.isArray(res.data) ? res.data : [])).catch(() => setFeeds([]))
    }
  }

  const handleCreate = async () => {
    try {
      await api.post('/api/v1/threat-intel/feeds', formData)
      setFormData({ name: '', source: 'abuseipdb', api_key: '', enabled: true })
      setShowForm(false)
      loadFeeds()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create feed')
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Threat Intelligence Feeds</div>
          <div className="page-subtitle">Configure and manage threat intelligence feed integrations.</div>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          style={{
            padding: '6px 12px',
            borderRadius: 8,
            border: '1px solid #22c55e',
            background: 'rgba(34, 197, 94, 0.1)',
            color: '#22c55e',
            cursor: 'pointer',
            fontSize: 12,
          }}
        >
          {showForm ? 'Cancel' : '+ Add Feed'}
        </button>
      </div>
      {showForm && (
        <div style={{ marginBottom: 16, padding: 16, border: '1px solid #374151', borderRadius: 8 }}>
          <input
            type="text"
            value={formData.name}
            onChange={e => setFormData({ ...formData, name: e.target.value })}
            placeholder="Feed name"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <select
            value={formData.source}
            onChange={e => setFormData({ ...formData, source: e.target.value })}
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          >
            <option value="abuseipdb">AbuseIPDB</option>
            <option value="virustotal">VirusTotal</option>
            <option value="otx">AlienVault OTX</option>
            <option value="misp">MISP</option>
          </select>
          <input
            type="text"
            value={formData.api_key}
            onChange={e => setFormData({ ...formData, api_key: e.target.value })}
            placeholder="API Key"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <button
            onClick={handleCreate}
            style={{
              padding: '8px 16px',
              borderRadius: 6,
              border: 'none',
              background: '#22c55e',
              color: '#022c22',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Create Feed
          </button>
        </div>
      )}
      <table className="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Source</th>
            <th>Status</th>
            <th>Last Sync</th>
          </tr>
        </thead>
        <tbody>
          {feeds.length === 0 ? (
            <tr>
              <td colSpan={4} className="muted">
                No threat intelligence feeds configured.
              </td>
            </tr>
          ) : (
            feeds.map(feed => (
              <tr key={feed.id}>
                <td>{feed.name}</td>
                <td><span className="chip">{feed.source}</span></td>
                <td>
                  <span className={`status-pill ${feed.enabled ? '' : 'warn'}`}>
                    {feed.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </td>
                <td className="muted" style={{ fontSize: 11 }}>
                  {feed.last_sync ? new Date(feed.last_sync).toLocaleString() : 'Never'}
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </section>
  )
}

function HoneypotHealthPage() {
  const [honeypots, setHoneypots] = useState<any[]>([])
  const [healthData, setHealthData] = useState<Record<number, any>>({})

  useEffect(() => {
    loadHoneypots()
    const interval = setInterval(() => {
      loadHoneypots()
      honeypots.forEach(hp => loadHealth(hp.id))
    }, 10000)
    return () => clearInterval(interval)
  }, [])

  const loadHoneypots = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api.get('/api/v1/honeypots').then(res => {
        const hps = Array.isArray(res.data) ? res.data : []
        setHoneypots(hps)
        hps.forEach((hp: any) => loadHealth(hp.id))
      }).catch(() => setHoneypots([]))
    }
  }

  const loadHealth = async (hpId: number) => {
    try {
      const res = await api.get(`/api/v1/honeypots/${hpId}/health`)
      setHealthData(prev => ({ ...prev, [hpId]: res.data }))
    } catch (err) {
      // Ignore errors
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Honeypot Health Monitoring</div>
          <div className="page-subtitle">Monitor honeypot health and performance metrics.</div>
        </div>
      </div>
      <table className="table">
        <thead>
          <tr>
            <th>Honeypot</th>
            <th>Status</th>
            <th>Uptime</th>
            <th>Response Time</th>
            <th>Last Check</th>
          </tr>
        </thead>
        <tbody>
          {honeypots.length === 0 ? (
            <tr>
              <td colSpan={5} className="muted">
                No honeypots available.
              </td>
            </tr>
          ) : (
            honeypots.map(hp => {
              const health = healthData[hp.id]
              return (
                <tr key={hp.id}>
                  <td>{hp.name}</td>
                  <td>
                    <span className={`status-pill ${health?.status === 'healthy' ? '' : health?.status === 'degraded' ? 'warn' : 'error'}`}>
                      {health?.status || 'unknown'}
                    </span>
                  </td>
                  <td>{health?.uptime_percent?.toFixed(1) || 'N/A'}%</td>
                  <td>{health?.response_time_ms ? `${health.response_time_ms}ms` : 'N/A'}</td>
                  <td className="muted" style={{ fontSize: 11 }}>
                    {health?.last_check ? new Date(health.last_check).toLocaleString() : 'Never'}
                  </td>
                </tr>
              )
            })
          )}
        </tbody>
      </table>
    </section>
  )
}

function GeoBlockingPage() {
  const [rules, setRules] = useState<any[]>([])
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({ name: '', action: 'block', countries: [] as string[], enabled: true })

  useEffect(() => {
    loadRules()
  }, [])

  const loadRules = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api.get('/api/v1/geo-block-rules').then(res => setRules(Array.isArray(res.data) ? res.data : [])).catch(() => setRules([]))
    }
  }

  const handleCreate = async () => {
    try {
      await api.post('/api/v1/geo-block-rules', formData)
      setFormData({ name: '', action: 'block', countries: [], enabled: true })
      setShowForm(false)
      loadRules()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create rule')
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Geo-Blocking Rules</div>
          <div className="page-subtitle">Block or allow traffic based on geographic location.</div>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          style={{
            padding: '6px 12px',
            borderRadius: 8,
            border: '1px solid #22c55e',
            background: 'rgba(34, 197, 94, 0.1)',
            color: '#22c55e',
            cursor: 'pointer',
            fontSize: 12,
          }}
        >
          {showForm ? 'Cancel' : '+ Create Rule'}
        </button>
      </div>
      {showForm && (
        <div style={{ marginBottom: 16, padding: 16, border: '1px solid #374151', borderRadius: 8 }}>
          <input
            type="text"
            value={formData.name}
            onChange={e => setFormData({ ...formData, name: e.target.value })}
            placeholder="Rule name"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <select
            value={formData.action}
            onChange={e => setFormData({ ...formData, action: e.target.value })}
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          >
            <option value="block">Block</option>
            <option value="allow">Allow</option>
            <option value="alert">Alert Only</option>
          </select>
          <input
            type="text"
            value={formData.countries.join(',')}
            onChange={e => setFormData({ ...formData, countries: e.target.value.split(',').map(c => c.trim()).filter(c => c) })}
            placeholder="Country codes (comma-separated, e.g. CN, RU, KP)"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <button
            onClick={handleCreate}
            style={{
              padding: '8px 16px',
              borderRadius: 6,
              border: 'none',
              background: '#22c55e',
              color: '#022c22',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Create Rule
          </button>
        </div>
      )}
      <table className="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Action</th>
            <th>Countries</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {rules.length === 0 ? (
            <tr>
              <td colSpan={4} className="muted">
                No geo-blocking rules configured.
              </td>
            </tr>
          ) : (
            rules.map(rule => (
              <tr key={rule.id}>
                <td>{rule.name}</td>
                <td><span className="chip">{rule.action}</span></td>
                <td style={{ fontSize: 11 }}>{rule.countries?.join(', ') || 'All'}</td>
                <td>
                  <span className={`status-pill ${rule.enabled ? '' : 'warn'}`}>
                    {rule.enabled ? 'Active' : 'Disabled'}
                  </span>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </section>
  )
}

function SIEMIntegrationPage() {
  const [integrations, setIntegrations] = useState<any[]>([])
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({ name: '', siem_type: 'splunk', endpoint: '', api_key: '', enabled: true })

  useEffect(() => {
    loadIntegrations()
  }, [])

  const loadIntegrations = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api.get('/api/v1/siem-integrations').then(res => setIntegrations(Array.isArray(res.data) ? res.data : [])).catch(() => setIntegrations([]))
    }
  }

  const handleCreate = async () => {
    try {
      await api.post('/api/v1/siem-integrations', formData)
      setFormData({ name: '', siem_type: 'splunk', endpoint: '', api_key: '', enabled: true })
      setShowForm(false)
      loadIntegrations()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create integration')
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">SIEM Integration</div>
          <div className="page-subtitle">Integrate with SIEM systems for centralized logging and analysis.</div>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          style={{
            padding: '6px 12px',
            borderRadius: 8,
            border: '1px solid #22c55e',
            background: 'rgba(34, 197, 94, 0.1)',
            color: '#22c55e',
            cursor: 'pointer',
            fontSize: 12,
          }}
        >
          {showForm ? 'Cancel' : '+ Add Integration'}
        </button>
      </div>
      {showForm && (
        <div style={{ marginBottom: 16, padding: 16, border: '1px solid #374151', borderRadius: 8 }}>
          <input
            type="text"
            value={formData.name}
            onChange={e => setFormData({ ...formData, name: e.target.value })}
            placeholder="Integration name"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <select
            value={formData.siem_type}
            onChange={e => setFormData({ ...formData, siem_type: e.target.value })}
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          >
            <option value="splunk">Splunk</option>
            <option value="qradar">QRadar</option>
            <option value="arcsight">ArcSight</option>
            <option value="logrhythm">LogRhythm</option>
            <option value="zabbix">Zabbix</option>
            <option value="logsign">Logsign</option>
            <option value="elasticsearch">Elasticsearch</option>
            <option value="graylog">Graylog</option>
            <option value="wazuh">Wazuh</option>
            <option value="ossim">OSSIM</option>
            <option value="securityonion">Security Onion</option>
            <option value="generic">Generic (HTTP/HTTPS)</option>
          </select>
          <input
            type="text"
            value={formData.endpoint}
            onChange={e => setFormData({ ...formData, endpoint: e.target.value })}
            placeholder="SIEM endpoint URL"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <input
            type="text"
            value={formData.api_key}
            onChange={e => setFormData({ ...formData, api_key: e.target.value })}
            placeholder="API Key (optional)"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <button
            onClick={handleCreate}
            style={{
              padding: '8px 16px',
              borderRadius: 6,
              border: 'none',
              background: '#22c55e',
              color: '#022c22',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Create Integration
          </button>
        </div>
      )}
      <table className="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>SIEM Type</th>
            <th>Endpoint</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {integrations.length === 0 ? (
            <tr>
              <td colSpan={4} className="muted">
                No SIEM integrations configured.
              </td>
            </tr>
          ) : (
            integrations.map(integration => (
              <tr key={integration.id}>
                <td>{integration.name}</td>
                <td><span className="chip">{integration.siem_type}</span></td>
                <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{integration.endpoint}</td>
                <td>
                  <div style={{ display: 'flex', gap: 4 }}>
                    <span className={`status-pill ${integration.enabled ? '' : 'warn'}`}>
                      {integration.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                    <button
                      onClick={async () => {
                        try {
                          const res = await api.post(`/api/v1/siem-integrations/${integration.id}/test`)
                          alert('Test result: ' + JSON.stringify(res.data.test_result, null, 2))
                        } catch (err: any) {
                          alert(err.response?.data?.detail || 'Test failed')
                        }
                      }}
                      style={{
                        padding: '4px 8px',
                        fontSize: 10,
                        borderRadius: 4,
                        border: '1px solid #3b82f6',
                        background: 'rgba(59, 130, 246, 0.1)',
                        color: '#3b82f6',
                        cursor: 'pointer',
                      }}
                    >
                      Test
                    </button>
                  </div>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </section>
  )
}

function CompliancePage() {
  const [reports, setReports] = useState<any[]>([])
  const [selectedType, setSelectedType] = useState('')

  useEffect(() => {
    loadReports()
  }, [selectedType])

  const loadReports = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      const url = selectedType ? `/api/v1/compliance-reports?compliance_type=${selectedType}` : '/api/v1/compliance-reports'
      api.get(url).then(res => setReports(Array.isArray(res.data) ? res.data : [])).catch(() => setReports([]))
    }
  }

  const generateReport = async (type: string) => {
    try {
      await api.post('/api/v1/compliance-reports/generate', null, { params: { compliance_type: type } })
      loadReports()
      alert('Compliance report generated successfully')
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to generate report')
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Compliance Reports</div>
          <div className="page-subtitle">Generate compliance reports for GDPR, HIPAA, PCI-DSS, and ISO 27001.</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={() => generateReport('gdpr')}
            style={{
              padding: '6px 12px',
              borderRadius: 8,
              border: '1px solid #22c55e',
              background: 'rgba(34, 197, 94, 0.1)',
              color: '#22c55e',
              cursor: 'pointer',
              fontSize: 11,
            }}
          >
            Generate GDPR
          </button>
          <button
            onClick={() => generateReport('hipaa')}
            style={{
              padding: '6px 12px',
              borderRadius: 8,
              border: '1px solid #22c55e',
              background: 'rgba(34, 197, 94, 0.1)',
              color: '#22c55e',
              cursor: 'pointer',
              fontSize: 11,
            }}
          >
            Generate HIPAA
          </button>
          <button
            onClick={() => generateReport('pci_dss')}
            style={{
              padding: '6px 12px',
              borderRadius: 8,
              border: '1px solid #22c55e',
              background: 'rgba(34, 197, 94, 0.1)',
              color: '#22c55e',
              cursor: 'pointer',
              fontSize: 11,
            }}
          >
            Generate PCI-DSS
          </button>
          <button
            onClick={() => generateReport('iso27001')}
            style={{
              padding: '6px 12px',
              borderRadius: 8,
              border: '1px solid #22c55e',
              background: 'rgba(34, 197, 94, 0.1)',
              color: '#22c55e',
              cursor: 'pointer',
              fontSize: 11,
            }}
          >
            Generate ISO 27001
          </button>
        </div>
      </div>
      <div style={{ marginBottom: 16 }}>
        <select
          value={selectedType}
          onChange={e => setSelectedType(e.target.value)}
          style={{
            padding: '8px 12px',
            borderRadius: 6,
            border: '1px solid #4b5563',
            background: '#020617',
            color: 'white',
            fontSize: 12,
          }}
        >
          <option value="">All Compliance Types</option>
          <option value="gdpr">GDPR</option>
          <option value="hipaa">HIPAA</option>
          <option value="pci_dss">PCI-DSS</option>
          <option value="iso27001">ISO 27001</option>
        </select>
      </div>
      <table className="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Compliance Type</th>
            <th>Generated At</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {reports.length === 0 ? (
            <tr>
              <td colSpan={4} className="muted">
                No compliance reports generated yet.
              </td>
            </tr>
          ) : (
            reports.map(report => (
              <tr key={report.id}>
                <td>{report.name}</td>
                <td><span className="chip">{report.compliance_type.toUpperCase()}</span></td>
                <td className="muted" style={{ fontSize: 11 }}>
                  {new Date(report.generated_at).toLocaleString()}
                </td>
                <td>
                  <button
                    onClick={() => alert('Report details: ' + JSON.stringify(report.report_data, null, 2))}
                    style={{
                      padding: '4px 8px',
                      fontSize: 10,
                      borderRadius: 4,
                      border: '1px solid #4b5563',
                      background: 'rgba(15, 23, 42, 0.9)',
                      color: '#e5e7eb',
                      cursor: 'pointer',
                    }}
                  >
                    View
                  </button>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </section>
  )
}

function AdvancedAnalyticsPage() {
  const [heatmapData, setHeatmapData] = useState<any>(null)
  const [trendsData, setTrendsData] = useState<any>(null)
  const [patterns, setPatterns] = useState<any[]>([])

  useEffect(() => {
    loadAnalytics()
    const interval = setInterval(loadAnalytics, 30000)
    return () => clearInterval(interval)
  }, [])

  const loadAnalytics = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      Promise.all([
        api.get('/api/v1/analytics/heatmap?days=7'),
        api.get('/api/v1/analytics/trends?days=30'),
        api.get('/api/v1/analytics/top-patterns?limit=10'),
      ]).then(([heatmapRes, trendsRes, patternsRes]) => {
        setHeatmapData(heatmapRes.data)
        setTrendsData(trendsRes.data)
        setPatterns(Array.isArray(patternsRes.data) ? patternsRes.data : [])
      }).catch(() => {})
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Advanced Analytics</div>
          <div className="page-subtitle">Attack correlation, trends, and pattern analysis.</div>
        </div>
      </div>
      {trendsData && (
        <div style={{ marginBottom: 24, padding: 16, background: 'rgba(15, 23, 42, 0.9)', borderRadius: 8, border: '1px solid #374151' }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>Attack Trends</div>
          <div style={{ fontSize: 12 }}>
            <div>Total Events: {trendsData.total_events}</div>
            <div>Trend: <span style={{ color: trendsData.trend === 'increasing' ? '#ef4444' : trendsData.trend === 'decreasing' ? '#22c55e' : '#f59e0b' }}>{trendsData.trend}</span></div>
          </div>
        </div>
      )}
      {patterns.length > 0 && (
        <div style={{ marginBottom: 24 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>Top Attack Patterns</div>
          <table className="table">
            <thead>
              <tr>
                <th>Pattern</th>
                <th>Count</th>
                <th>Percentage</th>
              </tr>
            </thead>
            <tbody>
              {patterns.map((pattern: any, idx: number) => (
                <tr key={idx}>
                  <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{pattern.pattern}</td>
                  <td>{pattern.count}</td>
                  <td>{pattern.percentage.toFixed(2)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

function ThreatActorsPage() {
  const [actors, setActors] = useState<any[]>([])
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({ name: '', techniques: [] as string[], aliases: [] as string[] })

  useEffect(() => {
    loadActors()
  }, [])

  const loadActors = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api.get('/api/v1/threat-actors').then(res => setActors(Array.isArray(res.data) ? res.data : [])).catch(() => setActors([]))
    }
  }

  const handleCreate = async () => {
    try {
      await api.post('/api/v1/threat-actors', formData)
      setFormData({ name: '', techniques: [], aliases: [] })
      setShowForm(false)
      loadActors()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create threat actor')
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Threat Actors</div>
          <div className="page-subtitle">Manage threat actor profiles and attribution.</div>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          style={{
            padding: '6px 12px',
            borderRadius: 8,
            border: '1px solid #22c55e',
            background: 'rgba(34, 197, 94, 0.1)',
            color: '#22c55e',
            cursor: 'pointer',
            fontSize: 12,
          }}
        >
          {showForm ? 'Cancel' : '+ Add Threat Actor'}
        </button>
      </div>
      {showForm && (
        <div style={{ marginBottom: 16, padding: 16, border: '1px solid #374151', borderRadius: 8 }}>
          <input
            type="text"
            value={formData.name}
            onChange={e => setFormData({ ...formData, name: e.target.value })}
            placeholder="Threat actor name"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <input
            type="text"
            value={formData.techniques.join(',')}
            onChange={e => setFormData({ ...formData, techniques: e.target.value.split(',').map(t => t.trim()).filter(t => t) })}
            placeholder="MITRE techniques (comma-separated, e.g. T1059, T1021)"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <input
            type="text"
            value={formData.aliases.join(',')}
            onChange={e => setFormData({ ...formData, aliases: e.target.value.split(',').map(a => a.trim()).filter(a => a) })}
            placeholder="Aliases (comma-separated)"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <button
            onClick={handleCreate}
            style={{
              padding: '8px 16px',
              borderRadius: 6,
              border: 'none',
              background: '#22c55e',
              color: '#022c22',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Create Threat Actor
          </button>
        </div>
      )}
      <table className="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Techniques</th>
            <th>Aliases</th>
            <th>Created</th>
          </tr>
        </thead>
        <tbody>
          {actors.length === 0 ? (
            <tr>
              <td colSpan={4} className="muted">
                No threat actors defined.
              </td>
            </tr>
          ) : (
            actors.map(actor => (
              <tr key={actor.id}>
                <td style={{ fontWeight: 600 }}>{actor.name}</td>
                <td style={{ fontSize: 11 }}>{(actor.techniques || []).join(', ')}</td>
                <td style={{ fontSize: 11 }}>{(actor.aliases || []).join(', ') || 'None'}</td>
                <td className="muted" style={{ fontSize: 11 }}>
                  {new Date(actor.created_at).toLocaleDateString()}
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </section>
  )
}

function YARARulesPage() {
  const [rules, setRules] = useState<any[]>([])
  const [matches, setMatches] = useState<Record<number, any[]>>({})
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({ name: '', rule_content: '', enabled: true })

  useEffect(() => {
    loadRules()
  }, [])

  const loadRules = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api.get('/api/v1/yara-rules').then(res => setRules(Array.isArray(res.data) ? res.data : [])).catch(() => setRules([]))
    }
  }

  const loadMatches = async (ruleId: number) => {
    try {
      const res = await api.get(`/api/v1/yara-rules/${ruleId}/matches`)
      setMatches(prev => ({ ...prev, [ruleId]: Array.isArray(res.data) ? res.data : [] }))
    } catch (err) {
      // Ignore
    }
  }

  const handleCreate = async () => {
    try {
      await api.post('/api/v1/yara-rules', formData)
      setFormData({ name: '', rule_content: '', enabled: true })
      setShowForm(false)
      loadRules()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create YARA rule')
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">YARA Rules</div>
          <div className="page-subtitle">Manage YARA rules for pattern matching.</div>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          style={{
            padding: '6px 12px',
            borderRadius: 8,
            border: '1px solid #22c55e',
            background: 'rgba(34, 197, 94, 0.1)',
            color: '#22c55e',
            cursor: 'pointer',
            fontSize: 12,
          }}
        >
          {showForm ? 'Cancel' : '+ Add Rule'}
        </button>
      </div>
      {showForm && (
        <div style={{ marginBottom: 16, padding: 16, border: '1px solid #374151', borderRadius: 8 }}>
          <input
            type="text"
            value={formData.name}
            onChange={e => setFormData({ ...formData, name: e.target.value })}
            placeholder="Rule name"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <textarea
            value={formData.rule_content}
            onChange={e => setFormData({ ...formData, rule_content: e.target.value })}
            placeholder="YARA rule content"
            rows={6}
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
              fontFamily: 'monospace',
            }}
          />
          <button
            onClick={handleCreate}
            style={{
              padding: '8px 16px',
              borderRadius: 6,
              border: 'none',
              background: '#22c55e',
              color: '#022c22',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Create Rule
          </button>
        </div>
      )}
      <table className="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {rules.length === 0 ? (
            <tr>
              <td colSpan={3} className="muted">
                No YARA rules defined.
              </td>
            </tr>
          ) : (
            rules.map(rule => (
              <tr key={rule.id}>
                <td>{rule.name}</td>
                <td>
                  <span className={`status-pill ${rule.enabled ? '' : 'warn'}`}>
                    {rule.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </td>
                <td>
                  <button
                    onClick={() => loadMatches(rule.id)}
                    style={{
                      padding: '4px 8px',
                      fontSize: 10,
                      borderRadius: 4,
                      border: '1px solid #3b82f6',
                      background: 'rgba(59, 130, 246, 0.1)',
                      color: '#3b82f6',
                      cursor: 'pointer',
                    }}
                  >
                    View Matches
                  </button>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </section>
  )
}

function RateLimitingPage() {
  const [rules, setRules] = useState<any[]>([])
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({ name: '', rule_type: 'ip', max_requests: 10, time_window: 60, action: 'block', enabled: true })

  useEffect(() => {
    loadRules()
  }, [])

  const loadRules = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api.get('/api/v1/rate-limit-rules').then(res => setRules(Array.isArray(res.data) ? res.data : [])).catch(() => setRules([]))
    }
  }

  const handleCreate = async () => {
    try {
      await api.post('/api/v1/rate-limit-rules', {
        name: formData.name,
        rule_type: formData.rule_type,
        conditions: {
          max_requests: formData.max_requests,
          time_window: formData.time_window,
        },
        action: formData.action,
        enabled: formData.enabled,
      })
      setFormData({ name: '', rule_type: 'ip', max_requests: 10, time_window: 60, action: 'block', enabled: true })
      setShowForm(false)
      loadRules()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create rate limit rule')
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Rate Limiting</div>
          <div className="page-subtitle">Configure rate limiting rules to prevent abuse.</div>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          style={{
            padding: '6px 12px',
            borderRadius: 8,
            border: '1px solid #22c55e',
            background: 'rgba(34, 197, 94, 0.1)',
            color: '#22c55e',
            cursor: 'pointer',
            fontSize: 12,
          }}
        >
          {showForm ? 'Cancel' : '+ Create Rule'}
        </button>
      </div>
      {showForm && (
        <div style={{ marginBottom: 16, padding: 16, border: '1px solid #374151', borderRadius: 8 }}>
          <input
            type="text"
            value={formData.name}
            onChange={e => setFormData({ ...formData, name: e.target.value })}
            placeholder="Rule name"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <select
            value={formData.rule_type}
            onChange={e => setFormData({ ...formData, rule_type: e.target.value })}
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          >
            <option value="ip">IP Address</option>
            <option value="event_type">Event Type</option>
            <option value="honeypot">Honeypot</option>
          </select>
          <input
            type="number"
            value={formData.max_requests}
            onChange={e => setFormData({ ...formData, max_requests: parseInt(e.target.value) || 10 })}
            placeholder="Max requests"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <input
            type="number"
            value={formData.time_window}
            onChange={e => setFormData({ ...formData, time_window: parseInt(e.target.value) || 60 })}
            placeholder="Time window (seconds)"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <select
            value={formData.action}
            onChange={e => setFormData({ ...formData, action: e.target.value })}
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          >
            <option value="block">Block</option>
            <option value="alert">Alert Only</option>
            <option value="throttle">Throttle</option>
          </select>
          <button
            onClick={handleCreate}
            style={{
              padding: '8px 16px',
              borderRadius: 6,
              border: 'none',
              background: '#22c55e',
              color: '#022c22',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Create Rule
          </button>
        </div>
      )}
      <table className="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Limit</th>
            <th>Action</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {rules.length === 0 ? (
            <tr>
              <td colSpan={5} className="muted">
                No rate limiting rules configured.
              </td>
            </tr>
          ) : (
            rules.map(rule => (
              <tr key={rule.id}>
                <td>{rule.name}</td>
                <td><span className="chip">{rule.rule_type}</span></td>
                <td>{rule.conditions?.max_requests || 0}/{rule.conditions?.time_window || 0}s</td>
                <td><span className="chip">{rule.action}</span></td>
                <td>
                  <span className={`status-pill ${rule.enabled ? '' : 'warn'}`}>
                    {rule.enabled ? 'Active' : 'Disabled'}
                  </span>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </section>
  )
}

function HoneytokensPage() {
  const [tokens, setTokens] = useState<any[]>([])
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({ name: '', token_type: 'credential' })

  useEffect(() => {
    loadTokens()
    const interval = setInterval(loadTokens, 10000)
    return () => clearInterval(interval)
  }, [])

  const loadTokens = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api.get('/api/v1/honeytokens').then(res => setTokens(Array.isArray(res.data) ? res.data : [])).catch(() => setTokens([]))
    }
  }

  const handleCreate = async () => {
    try {
      await api.post('/api/v1/honeytokens', formData)
      setFormData({ name: '', token_type: 'credential' })
      setShowForm(false)
      loadTokens()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create honeytoken')
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Honeytokens</div>
          <div className="page-subtitle">Manage honeytokens to detect credential theft and data exfiltration.</div>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          style={{
            padding: '6px 12px',
            borderRadius: 8,
            border: '1px solid #22c55e',
            background: 'rgba(34, 197, 94, 0.1)',
            color: '#22c55e',
            cursor: 'pointer',
            fontSize: 12,
          }}
        >
          {showForm ? 'Cancel' : '+ Create Honeytoken'}
        </button>
      </div>
      {showForm && (
        <div style={{ marginBottom: 16, padding: 16, border: '1px solid #374151', borderRadius: 8 }}>
          <input
            type="text"
            value={formData.name}
            onChange={e => setFormData({ ...formData, name: e.target.value })}
            placeholder="Honeytoken name"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <select
            value={formData.token_type}
            onChange={e => setFormData({ ...formData, token_type: e.target.value })}
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          >
            <option value="credential">Credential</option>
            <option value="api_key">API Key</option>
            <option value="file">File</option>
            <option value="url">URL</option>
          </select>
          <button
            onClick={handleCreate}
            style={{
              padding: '8px 16px',
              borderRadius: 6,
              border: 'none',
              background: '#22c55e',
              color: '#022c22',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Create Honeytoken
          </button>
        </div>
      )}
      <table className="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Token Value</th>
            <th>Status</th>
            <th>Triggered At</th>
          </tr>
        </thead>
        <tbody>
          {tokens.length === 0 ? (
            <tr>
              <td colSpan={5} className="muted">
                No honeytokens created.
              </td>
            </tr>
          ) : (
            tokens.map(token => (
              <tr key={token.id}>
                <td>{token.name}</td>
                <td><span className="chip">{token.token_type}</span></td>
                <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{token.token_value.substring(0, 30)}...</td>
                <td>
                  <span className={`status-pill ${token.status === 'triggered' ? 'error' : token.status === 'active' ? '' : 'warn'}`}>
                    {token.status}
                  </span>
                </td>
                <td className="muted" style={{ fontSize: 11 }}>
                  {token.triggered_at ? new Date(token.triggered_at).toLocaleString() : 'Never'}
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </section>
  )
}

function WebhooksPage() {
  const [webhooks, setWebhooks] = useState<any[]>([])
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({ name: '', url: '', events: [] as string[], secret: '', enabled: true })

  useEffect(() => {
    loadWebhooks()
  }, [])

  const loadWebhooks = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api.get('/api/v1/webhooks').then(res => setWebhooks(Array.isArray(res.data) ? res.data : [])).catch(() => setWebhooks([]))
    }
  }

  const handleCreate = async () => {
    try {
      await api.post('/api/v1/webhooks', formData)
      setFormData({ name: '', url: '', events: [], secret: '', enabled: true })
      setShowForm(false)
      loadWebhooks()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create webhook')
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Webhooks</div>
          <div className="page-subtitle">Configure webhooks for real-time event notifications.</div>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          style={{
            padding: '6px 12px',
            borderRadius: 8,
            border: '1px solid #22c55e',
            background: 'rgba(34, 197, 94, 0.1)',
            color: '#22c55e',
            cursor: 'pointer',
            fontSize: 12,
          }}
        >
          {showForm ? 'Cancel' : '+ Create Webhook'}
        </button>
      </div>
      {showForm && (
        <div style={{ marginBottom: 16, padding: 16, border: '1px solid #374151', borderRadius: 8 }}>
          <input
            type="text"
            value={formData.name}
            onChange={e => setFormData({ ...formData, name: e.target.value })}
            placeholder="Webhook name"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <input
            type="text"
            value={formData.url}
            onChange={e => setFormData({ ...formData, url: e.target.value })}
            placeholder="Webhook URL"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <input
            type="text"
            value={formData.events.join(',')}
            onChange={e => setFormData({ ...formData, events: e.target.value.split(',').map(e => e.trim()).filter(e => e) })}
            placeholder="Events (comma-separated, e.g. event_created, ioc_detected, alert_created)"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <input
            type="text"
            value={formData.secret}
            onChange={e => setFormData({ ...formData, secret: e.target.value })}
            placeholder="Secret (optional)"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <button
            onClick={handleCreate}
            style={{
              padding: '8px 16px',
              borderRadius: 6,
              border: 'none',
              background: '#22c55e',
              color: '#022c22',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Create Webhook
          </button>
        </div>
      )}
      <table className="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>URL</th>
            <th>Events</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {webhooks.length === 0 ? (
            <tr>
              <td colSpan={4} className="muted">
                No webhooks configured.
              </td>
            </tr>
          ) : (
            webhooks.map(webhook => (
              <tr key={webhook.id}>
                <td>{webhook.name}</td>
                <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{webhook.url.substring(0, 50)}...</td>
                <td style={{ fontSize: 11 }}>{(webhook.events || []).join(', ')}</td>
                <td>
                  <span className={`status-pill ${webhook.enabled ? '' : 'warn'}`}>
                    {webhook.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </section>
  )
}

function AuditLogsPage() {
  const [logs, setLogs] = useState<any[]>([])

  useEffect(() => {
    loadLogs()
    const interval = setInterval(loadLogs, 10000)
    return () => clearInterval(interval)
  }, [])

  const loadLogs = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api.get('/api/v1/audit-logs?limit=100').then(res => setLogs(Array.isArray(res.data) ? res.data : [])).catch(() => setLogs([]))
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Audit Logs</div>
          <div className="page-subtitle">System activity and user action logs.</div>
        </div>
      </div>
      <table className="table">
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>User</th>
            <th>Action</th>
            <th>Resource</th>
            <th>IP Address</th>
          </tr>
        </thead>
        <tbody>
          {logs.length === 0 ? (
            <tr>
              <td colSpan={5} className="muted">
                No audit logs available.
              </td>
            </tr>
          ) : (
            logs.map(log => (
              <tr key={log.id}>
                <td className="muted" style={{ fontSize: 11 }}>
                  {new Date(log.created_at).toLocaleString()}
                </td>
                <td>{log.user_id || 'System'}</td>
                <td><span className="chip">{log.action}</span></td>
                <td>{log.resource_type} {log.resource_id ? `#${log.resource_id}` : ''}</td>
                <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{log.ip_address || 'N/A'}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </section>
  )
}

function TagsPage() {
  const [tags, setTags] = useState<any[]>([])
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({ name: '', color: '#22c55e' })

  useEffect(() => {
    loadTags()
  }, [])

  const loadTags = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api.get('/api/v1/tags').then(res => setTags(Array.isArray(res.data) ? res.data : [])).catch(() => setTags([]))
    }
  }

  const handleCreate = async () => {
    try {
      await api.post('/api/v1/tags', formData)
      setFormData({ name: '', color: '#22c55e' })
      setShowForm(false)
      loadTags()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create tag')
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Tags</div>
          <div className="page-subtitle">Manage tags for events, IOCs, and honeypots.</div>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          style={{
            padding: '6px 12px',
            borderRadius: 8,
            border: '1px solid #22c55e',
            background: 'rgba(34, 197, 94, 0.1)',
            color: '#22c55e',
            cursor: 'pointer',
            fontSize: 12,
          }}
        >
          {showForm ? 'Cancel' : '+ Create Tag'}
        </button>
      </div>
      {showForm && (
        <div style={{ marginBottom: 16, padding: 16, border: '1px solid #374151', borderRadius: 8 }}>
          <input
            type="text"
            value={formData.name}
            onChange={e => setFormData({ ...formData, name: e.target.value })}
            placeholder="Tag name"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <input
            type="color"
            value={formData.color}
            onChange={e => setFormData({ ...formData, color: e.target.value })}
            style={{
              width: '100%',
              padding: '4px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              marginBottom: 8,
            }}
          />
          <button
            onClick={handleCreate}
            style={{
              padding: '8px 16px',
              borderRadius: 6,
              border: 'none',
              background: '#22c55e',
              color: '#022c22',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Create Tag
          </button>
        </div>
      )}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 12 }}>
        {tags.length === 0 ? (
          <div className="muted" style={{ gridColumn: '1 / -1', padding: 20, textAlign: 'center' }}>
            No tags. Create one to organize your data.
          </div>
        ) : (
          tags.map(tag => (
            <div
              key={tag.id}
              style={{
                padding: 12,
                border: '1px solid #374151',
                borderRadius: 8,
                background: 'rgba(15, 23, 42, 0.5)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <div
                  style={{
                    width: 16,
                    height: 16,
                    borderRadius: 4,
                    background: tag.color,
                  }}
                />
                <span style={{ fontSize: 14, fontWeight: 600 }}>{tag.name}</span>
              </div>
              <div className="muted" style={{ fontSize: 11 }}>
                Created {new Date(tag.created_at).toLocaleDateString()}
              </div>
            </div>
          ))
        )}
      </div>
    </section>
  )
}

function SuppressRulesPage() {
  const [rules, setRules] = useState<any[]>([])
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({ name: '', ip: '', event_type: '', duration_hours: 24 })

  useEffect(() => {
    loadRules()
    const interval = setInterval(loadRules, 10000)
    return () => clearInterval(interval)
  }, [])

  const loadRules = () => {
    const token = localStorage.getItem('token')
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api.get('/api/v1/suppress-rules').then(res => setRules(Array.isArray(res.data) ? res.data : [])).catch(() => setRules([]))
    }
  }

  const handleCreate = async () => {
    try {
      await api.post('/api/v1/suppress-rules', formData)
      setFormData({ name: '', ip: '', event_type: '', duration_hours: 24 })
      setShowForm(false)
      loadRules()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create suppress rule')
    }
  }

  const handleDelete = async (ruleId: number) => {
    if (!confirm('Delete this suppress rule?')) return
    try {
      await api.delete(`/api/v1/suppress-rules/${ruleId}`)
      loadRules()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to delete rule')
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Suppress Rules</div>
          <div className="page-subtitle">Temporarily suppress alerts from specific IPs or event types.</div>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          style={{
            padding: '6px 12px',
            borderRadius: 8,
            border: '1px solid #22c55e',
            background: 'rgba(34, 197, 94, 0.1)',
            color: '#22c55e',
            cursor: 'pointer',
            fontSize: 12,
          }}
        >
          {showForm ? 'Cancel' : '+ Create Rule'}
        </button>
      </div>
      {showForm && (
        <div style={{ marginBottom: 16, padding: 16, border: '1px solid #374151', borderRadius: 8 }}>
          <input
            type="text"
            value={formData.name}
            onChange={e => setFormData({ ...formData, name: e.target.value })}
            placeholder="Rule name"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <input
            type="text"
            value={formData.ip}
            onChange={e => setFormData({ ...formData, ip: e.target.value })}
            placeholder="IP address (optional, leave empty for all IPs)"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <input
            type="text"
            value={formData.event_type}
            onChange={e => setFormData({ ...formData, event_type: e.target.value })}
            placeholder="Event type (optional, e.g. ssh_connection, web_request)"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <input
            type="number"
            value={formData.duration_hours}
            onChange={e => setFormData({ ...formData, duration_hours: parseInt(e.target.value) || 24 })}
            placeholder="Duration (hours)"
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #4b5563',
              background: '#020617',
              color: 'white',
              marginBottom: 8,
              fontSize: 12,
            }}
          />
          <button
            onClick={handleCreate}
            style={{
              padding: '8px 16px',
              borderRadius: 6,
              border: 'none',
              background: '#22c55e',
              color: '#022c22',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Create Rule
          </button>
        </div>
      )}
      <table className="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>IP</th>
            <th>Event Type</th>
            <th>Duration</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {rules.length === 0 ? (
            <tr>
              <td colSpan={6} className="muted">
                No suppress rules. Create one to reduce alert noise.
              </td>
            </tr>
          ) : (
            rules.map(rule => (
              <tr key={rule.id}>
                <td>{rule.name}</td>
                <td style={{ fontFamily: 'monospace', fontSize: 11 }}>
                  {rule.conditions?.ip || 'Any'}
                </td>
                <td className="muted" style={{ fontSize: 11 }}>
                  {rule.conditions?.event_type || 'Any'}
                </td>
                <td className="muted" style={{ fontSize: 11 }}>
                  {rule.conditions?.duration_hours || 24}h
                </td>
                <td>
                  <span className={`status-pill ${rule.enabled ? '' : 'warn'}`}>
                    {rule.enabled ? 'Active' : 'Disabled'}
                  </span>
                </td>
                <td>
                  <button
                    onClick={() => handleDelete(rule.id)}
                    style={{
                      padding: '4px 8px',
                      fontSize: 10,
                      borderRadius: 4,
                      border: '1px solid #ef4444',
                      background: 'rgba(239, 68, 68, 0.1)',
                      color: '#ef4444',
                      cursor: 'pointer',
                    }}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </section>
  )
}

function LogsPage() {
  const [logs, setLogs] = useState<any[]>([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    loadLogs()
    const interval = setInterval(loadLogs, 5000)
    return () => clearInterval(interval)
  }, [])

  const loadLogs = () => {
    const token = localStorage.getItem('token')
    if (token) {
      setLoading(true)
      api.defaults.headers.common.Authorization = `Bearer ${token}`
      api
        .get('/api/v1/logs', { params: { limit: 100 } })
        .then(res => setLogs(Array.isArray(res.data.logs) ? res.data.logs : []))
        .catch(() => setLogs([]))
        .finally(() => setLoading(false))
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="page-title">Logs</div>
          <div className="page-subtitle">System and application logs.</div>
        </div>
        <button
          onClick={loadLogs}
          disabled={loading}
          style={{
            padding: '6px 12px',
            fontSize: 12,
            borderRadius: 6,
            border: '1px solid #4b5563',
            background: 'rgba(15, 23, 42, 0.9)',
            color: '#e5e7eb',
            cursor: loading ? 'not-allowed' : 'pointer',
          }}
        >
          {loading ? 'Loading...' : 'Refresh'}
        </button>
      </div>
      <div
        style={{
          padding: 12,
          background: '#020617',
          borderRadius: 8,
          border: '1px solid #374151',
          fontFamily: 'monospace',
          fontSize: 11,
          maxHeight: 600,
          overflowY: 'auto',
        }}
      >
        {logs.length === 0 ? (
          <div className="muted">No logs available.</div>
        ) : (
          logs.map((log, idx) => (
            <div key={idx} style={{ marginBottom: 8, color: '#9ca3af' }}>
              <span style={{ color: '#6b7280' }}>[{log.timestamp}]</span>{' '}
              <span style={{ color: log.level === 'ERROR' ? '#ef4444' : '#22c55e' }}>{log.level}</span>{' '}
              <span>{log.message}</span>
              {log.details && (
                <div style={{ marginLeft: 20, marginTop: 4, color: '#6b7280' }}>
                  {JSON.stringify(log.details, null, 2)}
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </section>
  )
}

export default function App() {
  return (
    <Routes>
      <Route path="/setup" element={<SetupWizard />} />
      <Route path="/login" element={<LoginPage />} />
      <Route element={<RequireAuth />}>
        <Route element={<LayoutShell />}>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/nodes" element={<NodesPage />} />
          <Route path="/honeypots" element={<HoneypotsPage />} />
          <Route path="/events" element={<EventsPage />} />
          <Route path="/iocs" element={<IocsPage />} />
          <Route path="/threat-map" element={<ThreatMapPage />} />
          <Route path="/alert-rules" element={<AlertRulesPage />} />
          <Route path="/blocked-ips" element={<BlockedIPsPage />} />
          <Route path="/webhooks" element={<WebhooksPage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/analytics" element={<AnalyticsPage />} />
          <Route path="/incidents" element={<IncidentsPage />} />
          <Route path="/mitre" element={<MITREPage />} />
          <Route path="/playbooks" element={<PlaybooksPage />} />
          <Route path="/campaigns" element={<CampaignsPage />} />
          <Route path="/attack-replay" element={<AttackReplayPage />} />
          <Route path="/detection-lab" element={<DetectionLabPage />} />
          <Route path="/ml-anomaly" element={<MLAnomalyPage />} />
          <Route path="/threat-intel" element={<ThreatIntelPage />} />
          <Route path="/honeypot-health" element={<HoneypotHealthPage />} />
          <Route path="/geo-blocking" element={<GeoBlockingPage />} />
          <Route path="/siem-integration" element={<SIEMIntegrationPage />} />
          <Route path="/compliance" element={<CompliancePage />} />
          <Route path="/analytics" element={<AdvancedAnalyticsPage />} />
          <Route path="/threat-actors" element={<ThreatActorsPage />} />
          <Route path="/yara-rules" element={<YARARulesPage />} />
          <Route path="/rate-limiting" element={<RateLimitingPage />} />
          <Route path="/honeytokens" element={<HoneytokensPage />} />
          <Route path="/webhooks" element={<WebhooksPage />} />
          <Route path="/audit-logs" element={<AuditLogsPage />} />
          <Route path="/tags" element={<TagsPage />} />
          <Route path="/suppress-rules" element={<SuppressRulesPage />} />
          <Route path="/logs" element={<LogsPage />} />
          <Route path="/users" element={<UsersPage />} />
          <Route path="/templates" element={<TemplatesPage />} />
          <Route path="/backups" element={<BackupsPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Route>
      </Route>
    </Routes>
  )
}
