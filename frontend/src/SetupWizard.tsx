import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'

const api = axios.create({
  baseURL: (import.meta as any).env?.VITE_API_URL || 'http://localhost:8000',
})

export default function SetupWizard() {
  const navigate = useNavigate()
  const [step, setStep] = useState(1)
  const [setupComplete, setSetupComplete] = useState(false)
  const [dbInfo, setDbInfo] = useState<any>(null)
  const [formData, setFormData] = useState({
    admin_email: '',
    admin_password: '',
    confirm_password: '',
    organization_name: 'Default Organization',
    smtp_host: '',
    smtp_port: 587,
    smtp_user: '',
    smtp_password: '',
  })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    // Get database info
    api.get('/api/v1/setup/database/info').then(res => {
      setDbInfo(res.data)
    }).catch((err) => {
      console.error('Database info error:', err)
      // Set default info if API fails
      setDbInfo({ status: 'error', error: 'Could not connect to database' })
    })
  }, [])

  const handleNext = () => {
    setError('') // Clear any previous errors
    if (step === 1) {
      // Step 1: Just move to step 2 (no validation needed for database)
      setStep(2)
    } else if (step === 2) {
      // Step 2: Validate email and passwords before moving to step 3
      if (!formData.admin_email || !formData.admin_email.includes('@')) {
        setError('Please enter a valid email address')
        return
      }
      if (formData.admin_password.length < 8) {
        setError('Password must be at least 8 characters')
        return
      }
      if (formData.admin_password !== formData.confirm_password) {
        setError('Passwords do not match')
        return
      }
      setStep(3)
    }
  }

  const handleComplete = async () => {
    setLoading(true)
    setError('')

    try {
      const payload: any = {
        admin_email: formData.admin_email,
        admin_password: formData.admin_password,
        organization_name: formData.organization_name,
      }
      
      // Only include SMTP fields if they have values
      if (formData.smtp_host && formData.smtp_host.trim()) {
        payload.smtp_host = formData.smtp_host
      }
      if (formData.smtp_port) {
        payload.smtp_port = formData.smtp_port
      }
      if (formData.smtp_user && formData.smtp_user.trim()) {
        payload.smtp_user = formData.smtp_user
      }
      if (formData.smtp_password && formData.smtp_password.trim()) {
        payload.smtp_password = formData.smtp_password
      }
      
      const response = await api.post('/api/v1/setup/complete', payload)

      if (response.data.status === 'success') {
        setSetupComplete(true)
        setTimeout(() => {
          navigate('/login')
        }, 2000)
      }
    } catch (err: any) {
      console.error('Setup error:', err)
      const errorDetail = err.response?.data?.detail
      if (Array.isArray(errorDetail)) {
        // Pydantic validation errors
        const errors = errorDetail.map((e: any) => {
          const field = Array.isArray(e.loc) ? e.loc.slice(1).join('.') : 'field'
          return `${field}: ${e.msg}`
        }).join(', ')
        setError(`Validation error: ${errors}`)
      } else if (typeof errorDetail === 'string') {
        setError(errorDetail)
      } else {
        setError(err.message || 'Setup failed. Please try again.')
      }
    } finally {
      setLoading(false)
    }
  }

  if (setupComplete) {
    return (
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '100vh',
        background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)',
      }}>
        <div style={{
          textAlign: 'center',
          padding: 40,
          background: 'rgba(15, 23, 42, 0.9)',
          borderRadius: 12,
          border: '1px solid #374151',
          maxWidth: 400,
        }}>
          <div style={{ fontSize: 48, marginBottom: 16 }}>✅</div>
          <h2 style={{ color: 'white', marginBottom: 8 }}>Setup Complete!</h2>
          <p style={{ color: '#9ca3af', fontSize: 14 }}>Redirecting to login...</p>
        </div>
      </div>
    )
  }

  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)',
      padding: 20,
    }}>
      <div style={{
        width: '100%',
        maxWidth: 500,
        background: 'rgba(15, 23, 42, 0.9)',
        borderRadius: 12,
        border: '1px solid #374151',
        padding: 32,
      }}>
        <div style={{ marginBottom: 24 }}>
          <h1 style={{ color: 'white', marginBottom: 8, fontSize: 24 }}>Welcome to Honeypot Platform</h1>
          <p style={{ color: '#9ca3af', fontSize: 14 }}>Let's set up your platform in a few steps</p>
        </div>

        {/* Progress indicator */}
        <div style={{ marginBottom: 32, display: 'flex', gap: 8 }}>
          {[1, 2, 3].map((s) => (
            <div
              key={s}
              style={{
                flex: 1,
                height: 4,
                background: s <= step ? '#22c55e' : '#374151',
                borderRadius: 2,
              }}
            />
          ))}
        </div>

        {error && (
          <div style={{
            padding: 12,
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid #ef4444',
            borderRadius: 6,
            color: '#fca5a5',
            fontSize: 13,
            marginBottom: 16,
          }}>
            {error}
          </div>
        )}

        {/* Step 1: Database Info */}
        {step === 1 && (
          <div>
            <h2 style={{ color: 'white', marginBottom: 16, fontSize: 18 }}>Database Configuration</h2>
            {dbInfo && dbInfo.status === 'success' && (
              <div style={{
                padding: 16,
                background: 'rgba(34, 197, 94, 0.1)',
                border: '1px solid #22c55e',
                borderRadius: 6,
                marginBottom: 16,
              }}>
                <div style={{ color: '#22c55e', fontSize: 13, marginBottom: 8 }}>✓ Database Connected</div>
                <div style={{ color: '#9ca3af', fontSize: 12 }}>
                  <div>Version: {dbInfo.version}</div>
                  <div>Tables: {dbInfo.table_count}</div>
                </div>
              </div>
            )}
            <p style={{ color: '#9ca3af', fontSize: 13, marginBottom: 16 }}>
              Using PostgreSQL database. Configuration is managed via environment variables.
            </p>
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <button
                onClick={handleNext}
                style={{
                  padding: '10px 20px',
                  background: '#22c55e',
                  color: 'white',
                  border: 'none',
                  borderRadius: 6,
                  cursor: 'pointer',
                  fontSize: 14,
                  fontWeight: 600,
                }}
              >
                Next →
              </button>
            </div>
          </div>
        )}

        {/* Step 2: Admin Account */}
        {step === 2 && (
          <div>
            <h2 style={{ color: 'white', marginBottom: 16, fontSize: 18 }}>Create Admin Account</h2>
            <p style={{ color: '#9ca3af', fontSize: 13, marginBottom: 16 }}>
              Create your administrator account to manage the platform.
            </p>
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', color: '#e5e7eb', fontSize: 13, marginBottom: 6 }}>
                Email Address
              </label>
              <input
                type="email"
                value={formData.admin_email}
                onChange={e => setFormData({ ...formData, admin_email: e.target.value })}
                placeholder="admin@example.com"
                style={{
                  width: '100%',
                  padding: '10px 12px',
                  background: '#020617',
                  border: '1px solid #4b5563',
                  borderRadius: 6,
                  color: 'white',
                  fontSize: 14,
                }}
              />
            </div>
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', color: '#e5e7eb', fontSize: 13, marginBottom: 6 }}>
                Password
              </label>
              <input
                type="password"
                value={formData.admin_password}
                onChange={e => setFormData({ ...formData, admin_password: e.target.value })}
                placeholder="Minimum 8 characters"
                style={{
                  width: '100%',
                  padding: '10px 12px',
                  background: '#020617',
                  border: '1px solid #4b5563',
                  borderRadius: 6,
                  color: 'white',
                  fontSize: 14,
                }}
              />
            </div>
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', color: '#e5e7eb', fontSize: 13, marginBottom: 6 }}>
                Confirm Password
              </label>
              <input
                type="password"
                value={formData.confirm_password}
                onChange={e => setFormData({ ...formData, confirm_password: e.target.value })}
                placeholder="Re-enter password"
                style={{
                  width: '100%',
                  padding: '10px 12px',
                  background: '#020617',
                  border: '1px solid #4b5563',
                  borderRadius: 6,
                  color: 'white',
                  fontSize: 14,
                }}
              />
            </div>
            <div style={{ display: 'flex', gap: 8, justifyContent: 'space-between' }}>
              <button
                onClick={() => setStep(1)}
                style={{
                  padding: '10px 20px',
                  background: 'transparent',
                  color: '#9ca3af',
                  border: '1px solid #4b5563',
                  borderRadius: 6,
                  cursor: 'pointer',
                  fontSize: 14,
                }}
              >
                ← Back
              </button>
              <button
                onClick={handleNext}
                style={{
                  padding: '10px 20px',
                  background: '#22c55e',
                  color: 'white',
                  border: 'none',
                  borderRadius: 6,
                  cursor: 'pointer',
                  fontSize: 14,
                  fontWeight: 600,
                }}
              >
                Next →
              </button>
            </div>
          </div>
        )}

        {/* Step 3: Organization & Optional Settings */}
        {step === 3 && (
          <div>
            <h2 style={{ color: 'white', marginBottom: 16, fontSize: 18 }}>Organization & Settings</h2>
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', color: '#e5e7eb', fontSize: 13, marginBottom: 6 }}>
                Organization Name
              </label>
              <input
                type="text"
                value={formData.organization_name}
                onChange={e => setFormData({ ...formData, organization_name: e.target.value })}
                placeholder="Default Organization"
                style={{
                  width: '100%',
                  padding: '10px 12px',
                  background: '#020617',
                  border: '1px solid #4b5563',
                  borderRadius: 6,
                  color: 'white',
                  fontSize: 14,
                }}
              />
            </div>
            <div style={{
              padding: 16,
              background: 'rgba(59, 130, 246, 0.1)',
              border: '1px solid #3b82f6',
              borderRadius: 6,
              marginBottom: 16,
            }}>
              <div style={{ color: '#3b82f6', fontSize: 13, marginBottom: 8 }}>ℹ️ Optional: Email Settings</div>
              <p style={{ color: '#9ca3af', fontSize: 12, marginBottom: 12 }}>
                Configure SMTP settings now or later in Settings page.
              </p>
              <div style={{ marginBottom: 12 }}>
                <input
                  type="text"
                  value={formData.smtp_host}
                  onChange={e => setFormData({ ...formData, smtp_host: e.target.value })}
                  placeholder="SMTP Host (e.g., smtp.gmail.com)"
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    background: '#020617',
                    border: '1px solid #4b5563',
                    borderRadius: 6,
                    color: 'white',
                    fontSize: 13,
                    marginBottom: 8,
                  }}
                />
                <input
                  type="number"
                  value={formData.smtp_port}
                  onChange={e => setFormData({ ...formData, smtp_port: parseInt(e.target.value) || 587 })}
                  placeholder="SMTP Port (e.g., 587)"
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    background: '#020617',
                    border: '1px solid #4b5563',
                    borderRadius: 6,
                    color: 'white',
                    fontSize: 13,
                    marginBottom: 8,
                  }}
                />
                <input
                  type="text"
                  value={formData.smtp_user}
                  onChange={e => setFormData({ ...formData, smtp_user: e.target.value })}
                  placeholder="SMTP Username"
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    background: '#020617',
                    border: '1px solid #4b5563',
                    borderRadius: 6,
                    color: 'white',
                    fontSize: 13,
                    marginBottom: 8,
                  }}
                />
                <input
                  type="password"
                  value={formData.smtp_password}
                  onChange={e => setFormData({ ...formData, smtp_password: e.target.value })}
                  placeholder="SMTP Password"
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    background: '#020617',
                    border: '1px solid #4b5563',
                    borderRadius: 6,
                    color: 'white',
                    fontSize: 13,
                  }}
                />
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8, justifyContent: 'space-between' }}>
              <button
                onClick={() => setStep(2)}
                style={{
                  padding: '10px 20px',
                  background: 'transparent',
                  color: '#9ca3af',
                  border: '1px solid #4b5563',
                  borderRadius: 6,
                  cursor: 'pointer',
                  fontSize: 14,
                }}
              >
                ← Back
              </button>
              <button
                onClick={handleComplete}
                disabled={loading}
                style={{
                  padding: '10px 20px',
                  background: loading ? '#4b5563' : '#22c55e',
                  color: 'white',
                  border: 'none',
                  borderRadius: 6,
                  cursor: loading ? 'not-allowed' : 'pointer',
                  fontSize: 14,
                  fontWeight: 600,
                }}
              >
                {loading ? 'Setting up...' : 'Complete Setup'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

