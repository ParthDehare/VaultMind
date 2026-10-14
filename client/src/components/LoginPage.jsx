import React, { useState } from 'react';
import { Loader2, Shield, Lock, User, Mail, Key, Sun, Moon, AlertCircle, CheckCircle } from 'lucide-react';

import { fetchWithAuth } from '../apiService';
import { authStore } from '../authStore';
import { useAppStore } from '../store';
import { DARK, LIGHT } from '../utils';

export default function LoginPage({ onLogin }) {
  const theme = useAppStore((s) => s.theme);
  const setTheme = useAppStore((s) => s.setTheme);
  const t = theme === 'dark' ? DARK : LIGHT;

  const [activeTab, setActiveTab] = useState('login'); // 'login' | 'signup'
  
  // Login states
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  
  // Signup states
  const [signupName, setSignupName] = useState('');
  const [signupEmail, setSignupEmail] = useState('');
  const [signupPassword, setSignupPassword] = useState('');
  const [signupRole, setSignupRole] = useState('analyst'); // 'analyst' | 'auditor'

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  const toggleTheme = () => {
    setTheme(theme === 'dark' ? 'light' : 'dark');
  };

  const handleLoginSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccessMsg('');
    
    try {
      const res = await fetchWithAuth('api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email: loginEmail, password: loginPassword }),
        headers: { 'Content-Type': 'application/json' }
      });
      
      const data = await res.json();
      
      if (!res.ok) {
        throw new Error(data.detail || 'Login failed. Please check your credentials.');
      }
      
      // Start Kafka Stream in background after successful login
      try {
        await fetchWithAuth('api/system/start-stream', {
          method: 'POST'
        });
      } catch (streamErr) {
        console.warn("Failed to start stream:", streamErr);
      }
      
      authStore.setAuth(data.user);
      onLogin(data.access_token, data.user);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSignupSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccessMsg('');

    try {
      const res = await fetchWithAuth('api/auth/signup', {
        method: 'POST',
        body: JSON.stringify({
          email: signupEmail,
          name: signupName,
          password: signupPassword,
          role: signupRole
        }),
        headers: { 'Content-Type': 'application/json' }
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.detail || 'Registration failed. Please check details.');
      }

      setSuccessMsg('Account registered successfully! Logging you in...');
      
      // Auto login
      setTimeout(async () => {
        try {
          const loginRes = await fetchWithAuth('api/auth/login', {
            method: 'POST',
            body: JSON.stringify({ email: signupEmail, password: signupPassword }),
            headers: { 'Content-Type': 'application/json' }
          });
          const loginData = await loginRes.json();
          if (loginRes.ok) {
            try {
              await fetchWithAuth('api/system/start-stream', { method: 'POST' });
            } catch (se) {}
            authStore.setAuth(loginData.user);
            onLogin(loginData.access_token, loginData.user);
          } else {
            setActiveTab('login');
            setLoginEmail(signupEmail);
            setLoginPassword('');
            setSuccessMsg('Registration successful! Please login below.');
          }
        } catch (err) {
          setActiveTab('login');
          setLoginEmail(signupEmail);
          setSuccessMsg('Registration successful! Please login below.');
        } finally {
          setLoading(false);
        }
      }, 1500);

    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  };

  return (
    <div 
      className="min-h-screen flex flex-col items-center justify-center relative overflow-hidden transition-all duration-300" 
      style={{ background: t.bg }}
    >
      {/* Background Mesh Gradients */}
      <div 
        className="absolute w-[500px] h-[500px] rounded-full blur-[120px] opacity-20 pointer-events-none transition-all duration-500" 
        style={{ 
          background: theme === 'dark' 
            ? 'radial-gradient(circle, rgba(99, 102, 241, 0.4) 0%, transparent 70%)'
            : 'radial-gradient(circle, rgba(99, 102, 241, 0.25) 0%, transparent 70%)',
          top: '-10%',
          left: '10%'
        }}
      />
      <div 
        className="absolute w-[600px] h-[600px] rounded-full blur-[140px] opacity-15 pointer-events-none transition-all duration-500" 
        style={{ 
          background: theme === 'dark' 
            ? 'radial-gradient(circle, rgba(239, 68, 68, 0.3) 0%, transparent 70%)'
            : 'radial-gradient(circle, rgba(239, 68, 68, 0.15) 0%, transparent 70%)',
          bottom: '-10%',
          right: '5%'
        }}
      />

      {/* Grid Overlay */}
      <div 
        className="absolute inset-0 pointer-events-none opacity-[0.03] transition-all duration-300"
        style={{ 
          backgroundImage: theme === 'dark' 
            ? 'linear-gradient(rgba(255, 255, 255, 0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(255, 255, 255, 0.1) 1px, transparent 1px)'
            : 'linear-gradient(rgba(15, 23, 42, 0.2) 1px, transparent 1px), linear-gradient(90deg, rgba(15, 23, 42, 0.2) 1px, transparent 1px)',
          backgroundSize: '32px 32px' 
        }}
      />

      {/* Top Controls Header */}
      <header className="absolute top-6 right-6 z-20">
        <button
          onClick={toggleTheme}
          className="w-10 h-10 rounded-xl border flex items-center justify-center cursor-pointer transition-all duration-200 shadow-sm"
          style={{ 
            background: t.card, 
            borderColor: t.border,
            color: t.text 
          }}
          title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
        >
          {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
        </button>
      </header>

      {/* Main Authentication Card */}
      <div 
        className="relative z-10 w-full max-w-md p-8 rounded-2xl border transition-all duration-300 mx-4" 
        style={{ 
          background: t.card, 
          borderColor: t.border,
          boxShadow: theme === 'dark' 
            ? '0 0 25px rgba(99, 102, 241, 0.12), 0 20px 50px rgba(0,0,0,0.5)'
            : '0 10px 30px rgba(99, 102, 241, 0.06), 0 4px 12px rgba(0, 0, 0, 0.03)'
        }}
      >
        {/* Portal Header */}
        <div className="text-center mb-8">

          <h2 className="text-2xl font-bold tracking-[3px] uppercase" style={{ color: t.text }}>VaultMind</h2>
          <p className="text-[10px] tracking-[2.5px] uppercase font-bold" style={{ color: t.text2 }}>Fraud Intelligence Portal 2.0</p>
        </div>

        {/* Tab switcher */}
        <div className="flex border-b mb-6" style={{ borderColor: t.border }}>
          <button
            onClick={() => { setActiveTab('login'); setError(''); setSuccessMsg(''); }}
            className="flex-1 pb-3 text-xs font-mono tracking-wider uppercase font-bold transition-all relative border-none bg-transparent cursor-pointer"
            style={{ color: activeTab === 'login' ? t.accent : t.text2 }}
          >
            Secure Login
            {activeTab === 'login' && (
              <span className="absolute bottom-0 left-0 right-0 h-[2px] rounded" style={{ background: t.accent }} />
            )}
          </button>
          <button
            onClick={() => { setActiveTab('signup'); setError(''); setSuccessMsg(''); }}
            className="flex-1 pb-3 text-xs font-mono tracking-wider uppercase font-bold transition-all relative border-none bg-transparent cursor-pointer"
            style={{ color: activeTab === 'signup' ? t.accent : t.text2 }}
          >
            Register Portal
            {activeTab === 'signup' && (
              <span className="absolute bottom-0 left-0 right-0 h-[2px] rounded" style={{ background: t.accent }} />
            )}
          </button>
        </div>

        {/* Form Container */}
        {activeTab === 'login' ? (
          <form onSubmit={handleLoginSubmit} className="space-y-5">
            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider mb-2" style={{ color: t.text2 }}>
                Employee Email / ID
              </label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: t.text2 }} />
                <input 
                  type="email" 
                  value={loginEmail}
                  onChange={(e) => setLoginEmail(e.target.value)}
                  className="w-full pl-10 pr-4 py-3 rounded-lg text-sm font-mono focus:outline-none transition-all border"
                  style={{ 
                    background: theme === 'dark' ? '#141620' : '#f8fafc',
                    borderColor: t.border,
                    color: t.text,
                  }}
                  placeholder="analyst@ubi.com"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider mb-2" style={{ color: t.text2 }}>
                Password
              </label>
              <div className="relative">
                <Key className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: t.text2 }} />
                <input 
                  type="password" 
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  className="w-full pl-10 pr-4 py-3 rounded-lg text-sm font-mono focus:outline-none transition-all border"
                  style={{ 
                    background: theme === 'dark' ? '#141620' : '#f8fafc',
                    borderColor: t.border,
                    color: t.text,
                  }}
                  placeholder="••••••••"
                  required
                />
              </div>
            </div>

            {error && (
              <div className="flex items-center gap-2 text-red-500 text-xs font-mono bg-red-500/10 p-3 rounded-lg border border-red-500/20">
                <AlertCircle size={14} className="shrink-0 animate-pulse" />
                <span>{error}</span>
              </div>
            )}

            {successMsg && (
              <div className="flex items-center gap-2 text-green-500 text-xs font-mono bg-green-500/10 p-3 rounded-lg border border-green-500/20">
                <CheckCircle size={14} className="shrink-0" />
                <span>{successMsg}</span>
              </div>
            )}

            <button 
              type="submit" 
              disabled={loading}
              className="w-full text-white font-bold py-3.5 rounded-lg text-xs tracking-widest uppercase transition-all flex items-center justify-center gap-2 mt-4 disabled:opacity-50 cursor-pointer border-none"
              style={{ background: t.accent }}
            >
              {loading ? <Loader2 size={14} className="animate-spin" /> : "Access Command Centre"}
            </button>
          </form>
        ) : (
          <form onSubmit={handleSignupSubmit} className="space-y-4">
            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider mb-1.5" style={{ color: t.text2 }}>
                Full Name
              </label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: t.text2 }} />
                <input 
                  type="text" 
                  value={signupName}
                  onChange={(e) => setSignupName(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 rounded-lg text-sm font-mono focus:outline-none transition-all border"
                  style={{ 
                    background: theme === 'dark' ? '#141620' : '#f8fafc',
                    borderColor: t.border,
                    color: t.text,
                  }}
                  placeholder="Jane Doe"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider mb-1.5" style={{ color: t.text2 }}>
                Employee Email
              </label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: t.text2 }} />
                <input 
                  type="email" 
                  value={signupEmail}
                  onChange={(e) => setSignupEmail(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 rounded-lg text-sm font-mono focus:outline-none transition-all border"
                  style={{ 
                    background: theme === 'dark' ? '#141620' : '#f8fafc',
                    borderColor: t.border,
                    color: t.text,
                  }}
                  placeholder="jane.doe@ubi.com"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider mb-1.5" style={{ color: t.text2 }}>
                Password
              </label>
              <div className="relative">
                <Key className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: t.text2 }} />
                <input 
                  type="password" 
                  value={signupPassword}
                  onChange={(e) => setSignupPassword(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 rounded-lg text-sm font-mono focus:outline-none transition-all border"
                  style={{ 
                    background: theme === 'dark' ? '#141620' : '#f8fafc',
                    borderColor: t.border,
                    color: t.text,
                  }}
                  placeholder="••••••••"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider mb-2" style={{ color: t.text2 }}>
                System Role
              </label>
              <div className="grid grid-cols-2 gap-3">
                <button
                  type="button"
                  onClick={() => setSignupRole('analyst')}
                  className="flex flex-col items-center p-3 rounded-lg border text-left transition-all cursor-pointer bg-transparent"
                  style={{ 
                    borderColor: signupRole === 'analyst' ? t.accent : t.border,
                    background: signupRole === 'analyst' ? (theme === 'dark' ? 'rgba(99,102,241,0.08)' : 'rgba(99,102,241,0.03)') : 'transparent'
                  }}
                >
                  <span className="text-xs font-mono font-bold" style={{ color: signupRole === 'analyst' ? t.accent : t.text }}>Analyst</span>
                  <span className="text-[8px] mt-1 text-center" style={{ color: t.text2 }}>Forensics & Investigation</span>
                </button>
                <button
                  type="button"
                  onClick={() => setSignupRole('auditor')}
                  className="flex flex-col items-center p-3 rounded-lg border text-left transition-all cursor-pointer bg-transparent"
                  style={{ 
                    borderColor: signupRole === 'auditor' ? t.accent : t.border,
                    background: signupRole === 'auditor' ? (theme === 'dark' ? 'rgba(99,102,241,0.08)' : 'rgba(99,102,241,0.03)') : 'transparent'
                  }}
                >
                  <span className="text-xs font-mono font-bold" style={{ color: signupRole === 'auditor' ? t.accent : t.text }}>Auditor</span>
                  <span className="text-[8px] mt-1 text-center" style={{ color: t.text2 }}>Strategic Oversight</span>
                </button>
              </div>
            </div>

            {error && (
              <div className="flex items-center gap-2 text-red-500 text-xs font-mono bg-red-500/10 p-3 rounded-lg border border-red-500/20">
                <AlertCircle size={14} className="shrink-0 animate-pulse" />
                <span>{error}</span>
              </div>
            )}

            {successMsg && (
              <div className="flex items-center gap-2 text-green-500 text-xs font-mono bg-green-500/10 p-3 rounded-lg border border-green-500/20">
                <CheckCircle size={14} className="shrink-0 animate-bounce" />
                <span>{successMsg}</span>
              </div>
            )}

            <button 
              type="submit" 
              disabled={loading}
              className="w-full text-white font-bold py-3 rounded-lg text-xs tracking-widest uppercase transition-all flex items-center justify-center gap-2 mt-4 disabled:opacity-50 cursor-pointer border-none"
              style={{ background: t.accent }}
            >
              {loading ? <Loader2 size={14} className="animate-spin" /> : "Register & Authenticate"}
            </button>
          </form>
        )}

        {/* Demo Credentials for Judges */}
        <div 
          className="mt-6 pt-4 border-t text-center rounded-xl p-3"
          style={{ 
            borderColor: t.border, 
            background: theme === 'dark' ? 'rgba(0,0,0,0.2)' : 'rgba(99,102,241,0.02)' 
          }}
        >
          <div className="text-[9px] uppercase tracking-widest mb-2 font-bold" style={{ color: t.text2 }}>Demo Credentials</div>
          <div className="flex flex-col gap-1.5">
            <div className="flex justify-between items-center text-[10px] font-mono">
              <span style={{ color: theme === 'dark' ? '#38bdf8' : '#0284c7' }}>Analyst (Forensics)</span>
              <span style={{ color: t.text2 }}>analyst@ubi.com / analyst123</span>
            </div>
            <div className="flex justify-between items-center text-[10px] font-mono">
              <span style={{ color: theme === 'dark' ? '#f87171' : '#dc2626' }}>Auditor (Authority)</span>
              <span style={{ color: t.text2 }}>auditor@ubi.com / auditor123</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
