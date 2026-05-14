import React, { useState, useEffect } from 'react';

const API_BASE = 'http://localhost:8000/api';

function CveModal({ cveId, onClose }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`)
      .then(r => r.json())
      .then(d => {
        const vuln = d.vulnerabilities?.[0]?.cve;
        if (!vuln) { setError('CVE nerasta'); setLoading(false); return; }
        const desc = vuln.descriptions?.find(d => d.lang === 'en')?.value || '—';
        const metrics = vuln.metrics?.cvssMetricV31?.[0] || vuln.metrics?.cvssMetricV30?.[0] || vuln.metrics?.cvssMetricV2?.[0];
        const score = metrics?.cvssData?.baseScore;
        const severity = metrics?.cvssData?.baseSeverity || metrics?.baseSeverity;
        const published = vuln.published?.split('T')[0];
        setData({ desc, score, severity, published });
        setLoading(false);
      })
      .catch(() => { setError('Nepavyko gauti CVE duomenų'); setLoading(false); });
  }, [cveId]);

  const severityColor = (s) => ({ CRITICAL: '#c0392b', HIGH: '#e74c3c', MEDIUM: '#e67e22', LOW: '#27ae60' }[s] || '#7b8a9a');

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '20px' }}
      onClick={onClose}>
      <div style={{ background: '#fff', borderRadius: '20px', padding: '32px', maxWidth: '560px', width: '100%', boxShadow: '0 20px 80px rgba(0,0,0,0.2)' }}
        onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '20px' }}>
          <div>
            <p style={{ margin: 0, color: '#7b8a9a', fontSize: '0.85rem' }}>Pažeidžiamumas</p>
            <h3 style={{ margin: '4px 0 0', color: '#1a1f36' }}>{cveId}</h3>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', fontSize: '1.4rem', cursor: 'pointer', color: '#7b8a9a' }}>×</button>
        </div>

        {loading && <p style={{ color: '#7b8a9a' }}>Kraunama...</p>}
        {error && <p style={{ color: '#c0392b' }}>{error}</p>}
        {data && (
          <div>
            <div style={{ display: 'flex', gap: '12px', marginBottom: '20px', flexWrap: 'wrap' }}>
              <div style={{ padding: '12px 20px', borderRadius: '12px', background: '#f4f7fb', textAlign: 'center', minWidth: '80px' }}>
                <p style={{ margin: 0, fontSize: '0.8rem', color: '#7b8a9a' }}>CVSS</p>
                <strong style={{ fontSize: '1.6rem', color: data.score ? severityColor(data.severity) : '#7b8a9a' }}>
                  {data.score || 'N/A'}
                </strong>
              </div>
              {data.severity && (
                <div style={{ padding: '12px 20px', borderRadius: '12px', background: '#f4f7fb', textAlign: 'center' }}>
                  <p style={{ margin: 0, fontSize: '0.8rem', color: '#7b8a9a' }}>Sunkumas</p>
                  <strong style={{ color: severityColor(data.severity) }}>{data.severity}</strong>
                </div>
              )}
              {data.published && (
                <div style={{ padding: '12px 20px', borderRadius: '12px', background: '#f4f7fb', textAlign: 'center' }}>
                  <p style={{ margin: 0, fontSize: '0.8rem', color: '#7b8a9a' }}>Paskelbta</p>
                  <strong style={{ color: '#1a1f36', fontSize: '0.95rem' }}>{data.published}</strong>
                </div>
              )}
            </div>
            <div style={{ maxHeight: '200px', overflowY: 'auto', color: '#2f4369', lineHeight: '1.6', marginBottom: '20px', paddingRight: '4px' }}>
              {data.desc}
            </div>
            <a href={`https://nvd.nist.gov/vuln/detail/${cveId}`} target="_blank" rel="noreferrer"
              style={{ display: 'inline-block', padding: '10px 20px', borderRadius: '10px', background: '#1f77d0', color: '#fff', fontWeight: 600, textDecoration: 'none' }}>
              Peržiūrėti NVD →
            </a>
          </div>
        )}
      </div>
    </div>
  );
}

function LoginForm({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [view, setView] = useState('login'); // login | forgot | reset | done
  const [email, setEmail] = useState('');
  const [msg, setMsg] = useState('');

  const params = new URLSearchParams(window.location.search);
  const resetUid = params.get('reset_uid');
  const resetToken = params.get('reset_token');
  const [newPassword, setNewPassword] = useState('');
  const [newPassword2, setNewPassword2] = useState('');

  useEffect(() => {
    if (resetUid && resetToken) setView('reset');
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    try {
      const res = await fetch(`${API_BASE}/login/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (data.token) {
        localStorage.setItem('auth_token', data.token);
        onLogin(data.token);
      } else {
        setError(data.error || 'Klaida');
      }
    } catch {
      setError('Nepavyko prisijungti');
    }
  };

  const [resetUrl, setResetUrl] = useState('');

  const handleForgot = async (e) => {
    e.preventDefault();
    setMsg('');
    setResetUrl('');
    const res = await fetch(`${API_BASE}/password-reset/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    const data = await res.json();
    if (data.reset_url) {
      setResetUrl(data.reset_url);
    } else {
      setMsg('Vartotojas su tokiu el. paštu nerastas.');
    }
  };

  const handleReset = async (e) => {
    e.preventDefault();
    if (newPassword !== newPassword2) { setError('Slaptažodžiai nesutampa'); return; }
    const res = await fetch(`${API_BASE}/password-reset/confirm/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ uid: resetUid, token: resetToken, password: newPassword }),
    });
    const data = await res.json();
    if (data.status === 'ok') {
      setView('done');
      window.history.replaceState({}, '', '/');
    } else {
      setError(data.error || 'Klaida');
    }
  };

  const inputStyle = { width: '100%', padding: '12px 16px', borderRadius: '12px', border: '1px solid #d7dceb', marginBottom: '12px', fontSize: '1rem', boxSizing: 'border-box' };

  return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', background: '#f4f7fb' }}>
      <div style={{ padding: '40px', borderRadius: '24px', background: '#fff', boxShadow: '0 20px 68px rgba(38,53,92,0.1)', width: '360px' }}>
        <p style={{ color: '#4780d0', fontWeight: 700, marginBottom: '8px' }}>Saugumo skeneris</p>

        {view === 'login' && <>
          <h2 style={{ margin: '0 0 24px', color: '#1a1f36' }}>Prisijungimas</h2>
          <form onSubmit={handleSubmit}>
            <input value={username} onChange={e => setUsername(e.target.value)} placeholder="Vartotojas" style={inputStyle} />
            <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Slaptažodis" style={{ ...inputStyle, marginBottom: '8px' }} />
            {error && <p style={{ color: '#c0392b', marginBottom: '12px' }}>{error}</p>}
            <button type="submit" style={{ width: '100%', padding: '14px', borderRadius: '12px', border: 'none', background: '#1f77d0', color: '#fff', fontWeight: 700, fontSize: '1rem', cursor: 'pointer', marginBottom: '12px' }}>
              Prisijungti
            </button>
          </form>
          <button onClick={() => setView('forgot')} style={{ background: 'none', border: 'none', color: '#1f77d0', cursor: 'pointer', fontSize: '0.9rem' }}>
            Pamiršote slaptažodį?
          </button>
        </>}

        {view === 'forgot' && <>
          <h2 style={{ margin: '0 0 24px', color: '#1a1f36' }}>Slaptažodžio atkūrimas</h2>
          <form onSubmit={handleForgot}>
            <input type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="El. paštas" style={inputStyle} />
            {msg && <p style={{ color: '#c0392b', marginBottom: '12px', fontSize: '0.9rem' }}>{msg}</p>}
            {resetUrl && (
              <div style={{ background: '#f4f7fb', borderRadius: '10px', padding: '12px', marginBottom: '12px', wordBreak: 'break-all' }}>
                <p style={{ margin: '0 0 8px', color: '#5c6d85', fontSize: '0.85rem', fontWeight: 600 }}>Atkūrimo nuoroda:</p>
                <a href={resetUrl} style={{ color: '#1f77d0', fontSize: '0.85rem' }}>{resetUrl}</a>
              </div>
            )}
            {!resetUrl && <button type="submit" style={{ width: '100%', padding: '14px', borderRadius: '12px', border: 'none', background: '#1f77d0', color: '#fff', fontWeight: 700, fontSize: '1rem', cursor: 'pointer', marginBottom: '12px' }}>
              Gauti atkūrimo nuorodą
            </button>}
          </form>
          <button onClick={() => setView('login')} style={{ background: 'none', border: 'none', color: '#7b8a9a', cursor: 'pointer', fontSize: '0.9rem' }}>← Atgal</button>
        </>}

        {view === 'reset' && <>
          <h2 style={{ margin: '0 0 24px', color: '#1a1f36' }}>Naujas slaptažodis</h2>
          <form onSubmit={handleReset}>
            <input type="password" value={newPassword} onChange={e => setNewPassword(e.target.value)} placeholder="Naujas slaptažodis" style={inputStyle} />
            <input type="password" value={newPassword2} onChange={e => setNewPassword2(e.target.value)} placeholder="Pakartokite slaptažodį" style={inputStyle} />
            {error && <p style={{ color: '#c0392b', marginBottom: '12px' }}>{error}</p>}
            <button type="submit" style={{ width: '100%', padding: '14px', borderRadius: '12px', border: 'none', background: '#1f77d0', color: '#fff', fontWeight: 700, fontSize: '1rem', cursor: 'pointer' }}>
              Keisti slaptažodį
            </button>
          </form>
        </>}

        {view === 'done' && <>
          <h2 style={{ margin: '0 0 16px', color: '#1a1f36' }}>Slaptažodis pakeistas</h2>
          <p style={{ color: '#27ae60', marginBottom: '20px' }}>Galite prisijungti su nauju slaptažodžiu.</p>
          <button onClick={() => setView('login')} style={{ width: '100%', padding: '14px', borderRadius: '12px', border: 'none', background: '#1f77d0', color: '#fff', fontWeight: 700, fontSize: '1rem', cursor: 'pointer' }}>
            Prisijungti
          </button>
        </>}
      </div>
    </div>
  );
}

function ScanResults({ rd }) {
  const hosts = rd.hosts || [];
  const firstWithPorts = hosts.findIndex(h => h.open_port_count > 0);
  const [activeHost, setActiveHost] = useState(firstWithPorts >= 0 ? firstWithPorts : 0);
  const [selectedCve, setSelectedCve] = useState(null);
  const [showInfo, setShowInfo] = useState(false);
  const vulns = rd.openvas?.vulnerabilities || [];
  const severityColor = (s) => s >= 7 ? '#c0392b' : s >= 4 ? '#e67e22' : s > 0 ? '#27ae60' : '#7b8a9a';
  const severityBg = (s) => s >= 7 ? '#fde8e8' : s >= 4 ? '#fff3e0' : '#e8f5e9';
  const severityLabel = (s) => s >= 7 ? 'Aukštas' : s >= 4 ? 'Vidutinis' : s > 0 ? 'Žemas' : 'Info';

  if (hosts.length === 0) return <p style={{ color: '#7b8a9a' }}>Dar nėra rezultatų.</p>;


  const host = hosts[activeHost] || hosts[0];
  const allVulns = Array.from(new Map(vulns.map(v => [v.name, v])).values());
  const hostVulns = showInfo ? allVulns : allVulns.filter(v => v.severity > 0 || (v.cves && v.cves.length > 0));
  const infoCount = allVulns.length - hostVulns.length;

  return (
    <div>
      {selectedCve && <CveModal cveId={selectedCve} onClose={() => setSelectedCve(null)} />}
      {hosts.length > 1 && (
        <div style={{ display: 'flex', gap: '8px', marginBottom: '16px', flexWrap: 'wrap' }}>
          {hosts.filter(h => h.open_port_count > 0).map((h, i) => (
            <button key={i} onClick={() => setActiveHost(hosts.indexOf(h))}
              style={{ padding: '8px 16px', borderRadius: '10px', border: '1px solid', cursor: 'pointer', fontWeight: 600, fontSize: '0.9rem',
                borderColor: hosts.indexOf(h) === activeHost ? '#1f77d0' : '#d7dceb',
                background: hosts.indexOf(h) === activeHost ? '#eef4ff' : '#fff',
                color: hosts.indexOf(h) === activeHost ? '#1f77d0' : '#5c6d85' }}>
              {h.ip} <span style={{ fontWeight: 400 }}>({h.open_port_count} portų)</span>
            </button>
          ))}
        </div>
      )}

      <div style={{ background: '#fff', borderRadius: '16px', overflow: 'hidden', marginBottom: '20px', boxShadow: '0 4px 20px rgba(38,53,92,0.05)' }}>
        <div style={{ padding: '16px 20px', background: '#f4f7fb', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <strong style={{ color: '#1a1f36' }}>{host.ip}</strong>
            <span style={{ marginLeft: '12px', color: '#7b8a9a', fontSize: '0.9rem' }}>{host.open_port_count} atvirų portų</span>
          </div>
          <span style={{ fontSize: '0.85rem', color: '#7b8a9a' }}>OpenVAS: {rd.openvas?.status || '—'}</span>
        </div>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ background: '#fafbfc' }}>
              <th style={{ padding: '10px 16px', textAlign: 'left', color: '#5c6d85', fontWeight: 600, fontSize: '0.88rem' }}>Portas</th>
              <th style={{ padding: '10px 16px', textAlign: 'left', color: '#5c6d85', fontWeight: 600, fontSize: '0.88rem' }}>Servisas</th>
              <th style={{ padding: '10px 16px', textAlign: 'left', color: '#5c6d85', fontWeight: 600, fontSize: '0.88rem' }}>Versija</th>
              <th style={{ padding: '10px 16px', textAlign: 'left', color: '#5c6d85', fontWeight: 600, fontSize: '0.88rem' }}>Būsena</th>
            </tr>
          </thead>
          <tbody>
            {(host.ports || []).map((p, i) => (
              <tr key={i} style={{ borderBottom: '1px solid #f0f4fa', background: p.state === 'open' ? '#f8fff8' : '#fff' }}>
                <td style={{ padding: '10px 16px', fontWeight: p.state === 'open' ? 700 : 400 }}>{p.port}</td>
                <td style={{ padding: '10px 16px' }}>{p.service}</td>
                <td style={{ padding: '10px 16px', color: '#7b8a9a', fontSize: '0.9rem' }}>{p.version || '—'}</td>
                <td style={{ padding: '10px 16px' }}>
                  <span style={{ color: p.state === 'open' ? '#116a0d' : '#a00', fontWeight: 600 }}>{p.state}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {allVulns.length > 0 && (
        <div style={{ background: '#fff', borderRadius: '16px', overflow: 'hidden', boxShadow: '0 4px 20px rgba(38,53,92,0.05)' }}>
          <div style={{ padding: '16px 20px', background: '#fff8f0', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <strong style={{ color: '#1a1f36' }}>OpenVAS rezultatai ({hostVulns.length})</strong>
            {infoCount > 0 && (
              <button onClick={() => setShowInfo(!showInfo)}
                style={{ padding: '4px 12px', borderRadius: '8px', border: '1px solid #e0c88a', background: showInfo ? '#fff3e0' : '#fff', color: '#e67e22', cursor: 'pointer', fontSize: '0.85rem' }}>
                {showInfo ? 'Slėpti' : `+ ${infoCount} Info`}
              </button>
            )}
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: '#fafbfc' }}>
                <th style={{ padding: '10px 16px', textAlign: 'left', color: '#5c6d85', fontWeight: 600, fontSize: '0.88rem' }}>Pavadinimas</th>
                <th style={{ padding: '10px 16px', textAlign: 'left', color: '#5c6d85', fontWeight: 600, fontSize: '0.88rem', width: '90px' }}>Portas</th>
                <th style={{ padding: '10px 16px', textAlign: 'left', color: '#5c6d85', fontWeight: 600, fontSize: '0.88rem' }}>CVE</th>
                <th style={{ padding: '10px 16px', textAlign: 'left', color: '#5c6d85', fontWeight: 600, fontSize: '0.88rem', width: '120px' }}>Sunkumas</th>
              </tr>
            </thead>
            <tbody>
              {hostVulns.map((v, i) => (
                <tr key={i} style={{ borderBottom: '1px solid #f0f4fa' }}>
                  <td style={{ padding: '10px 16px' }}>{v.name}</td>
                  <td style={{ padding: '10px 16px', color: '#5c6d85', fontSize: '0.9rem' }}>{v.port || '—'}</td>
                  <td style={{ padding: '10px 16px', fontSize: '0.85rem' }}>
                    {v.cves?.length > 0
                      ? v.cves.map((cve, j) => (
                          <button key={j} onClick={() => setSelectedCve(cve)}
                            style={{ marginRight: '6px', color: '#1f77d0', background: '#eef4ff', border: '1px solid #c3d9f7', borderRadius: '6px', padding: '2px 8px', cursor: 'pointer', fontSize: '0.82rem', fontWeight: 600 }}>
                            {cve}
                          </button>
                        ))
                      : <span style={{ color: '#aaa' }}>—</span>}
                  </td>
                  <td style={{ padding: '10px 16px' }}>
                    {v.severity > 0 ? (
                      <span style={{ padding: '3px 10px', borderRadius: '8px', fontSize: '0.82rem', fontWeight: 600, background: severityBg(v.severity), color: severityColor(v.severity) }}>
                        {severityLabel(v.severity)} ({v.severity})
                      </span>
                    ) : v.cves?.length > 0 ? (
                      <span style={{ padding: '3px 10px', borderRadius: '8px', fontSize: '0.82rem', fontWeight: 600, background: '#fff3e0', color: '#e67e22' }}>
                        ↑ Žiūrėti CVE
                      </span>
                    ) : (
                      <span style={{ padding: '3px 10px', borderRadius: '8px', fontSize: '0.82rem', fontWeight: 600, background: '#e8f5e9', color: '#27ae60' }}>
                        Info
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function VykdymasTab({ authHeaders }) {
  const [scans, setScans] = useState([]);
  const [scheduledProfiles, setScheduledProfiles] = useState([]);

  useEffect(() => {
    const load = () => {
      fetch(`${API_BASE}/results/`, { headers: authHeaders })
        .then(r => r.json())
        .then(d => setScans(d.results || []));
      fetch(`${API_BASE}/profiles/`, { headers: authHeaders })
        .then(r => r.json())
        .then(d => setScheduledProfiles((d.profiles || []).filter(p => p.schedule !== 'none')));
    };
    load();
    const interval = setInterval(load, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleStop = async (id) => {
    await fetch(`${API_BASE}/results/${id}/stop/`, { method: 'POST', headers: authHeaders });
  };

  const scheduleLabel = s => ({ hourly: 'Kas valandą', daily: 'Kas dieną', weekly: 'Kas savaitę' }[s] || s);
  const weekdayLabel = d => ['Pir','Ant','Tre','Ket','Pen','Šeš','Sek'][d] || '';

  const active = scans.filter(r => r.report_data?.scan_status === 'running');
  const recent = scans.filter(r => r.report_data?.scan_status !== 'running').slice(0, 3);

  return (
    <div>
      <h2 style={{ color: '#1a1f36', marginBottom: '20px' }}>Vykdymas ir stebėsena</h2>

      {active.length === 0 ? (
        <div style={{ padding: '28px', borderRadius: '20px', background: '#fff', textAlign: 'center', color: '#6f7b8a', border: '1px dashed #d7dceb', marginBottom: '28px' }}>
          Šiuo metu nėra aktyvių skenavimų. Pradėkite naują skenavimą skiltyje "Skenavimo profiliai".
        </div>
      ) : active.map(r => {
        const rd = r.report_data || {};
        const openvasProgress = rd.openvas_progress || 0;
        const nmapDone = (rd.hosts || []).length > 0;
        const stage = nmapDone ? 'openvas' : 'nmap';

        return (
          <div key={r.id} style={{ padding: '24px', borderRadius: '20px', background: '#fff', boxShadow: '0 18px 60px rgba(38,53,92,0.05)', marginBottom: '24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
              <div>
                <h3 style={{ margin: 0, color: '#1a1f36' }}>{rd.target}</h3>
                <p style={{ margin: '4px 0 0', color: '#7b8a9a', fontSize: '0.9rem' }}>
                  {stage === 'nmap' ? 'Nmap skenavimas vykdomas...' : `OpenVAS skenavimas... ${openvasProgress}%`}
                </p>
                <p style={{ margin: '2px 0 0', color: '#aab', fontSize: '0.82rem' }}>
                  Pradėta: {new Date(r.created_at).toLocaleString('lt-LT')}
                </p>
              </div>
              <button onClick={() => handleStop(r.id)}
                style={{ padding: '8px 20px', borderRadius: '10px', border: 'none', background: '#e74c3c', color: '#fff', fontWeight: 700, cursor: 'pointer' }}>
                Sustabdyti
              </button>
            </div>

            <div style={{ display: 'flex', gap: '8px', marginBottom: '20px' }}>
              {[
                { label: '1. Nmap', done: nmapDone, active: stage === 'nmap' },
                { label: '2. OpenVAS', done: false, active: stage === 'openvas' },
              ].map((step, i) => (
                <div key={i} style={{ flex: 1, padding: '10px 14px', borderRadius: '10px', border: '1px solid',
                  borderColor: step.done ? '#27ae60' : step.active ? '#1f77d0' : '#e0e7f0',
                  background: step.done ? '#e8f5e9' : step.active ? '#eef4ff' : '#f8f9fb' }}>
                  <span style={{ fontWeight: 600, fontSize: '0.88rem',
                    color: step.done ? '#27ae60' : step.active ? '#1f77d0' : '#aab' }}>
                    {step.done ? '✓ ' : step.active ? '● ' : '○ '}{step.label}
                  </span>
                  {step.active && stage === 'openvas' && (
                    <div style={{ marginTop: '6px', height: '6px', borderRadius: '4px', background: '#dce6f5', overflow: 'hidden' }}>
                      <div style={{ height: '100%', borderRadius: '4px', background: '#1f77d0', width: `${openvasProgress}%`, transition: 'width 0.5s ease' }} />
                    </div>
                  )}
                </div>
              ))}
            </div>

            {nmapDone && (
              <div>
                <h4 style={{ color: '#1a1f36', marginBottom: '12px' }}>Nmap rezultatai</h4>
                <ScanResults rd={rd} />
              </div>
            )}
          </div>
        );
      })}

      {recent.length > 0 && (
        <div>
          <h3 style={{ color: '#1a1f36', marginBottom: '16px' }}>Paskutiniai skenavimai</h3>
          {recent.map(r => {
            const rd = r.report_data || {};
            return (
              <div key={r.id} style={{ padding: '20px 24px', borderRadius: '20px', background: '#fff', boxShadow: '0 4px 20px rgba(38,53,92,0.05)', marginBottom: '16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                  <div>
                    <strong style={{ color: '#1a1f36' }}>{rd.target}</strong>
                    <span style={{ marginLeft: '12px', padding: '2px 10px', borderRadius: '8px', fontSize: '0.82rem', fontWeight: 600,
                      background: rd.scan_status === 'completed' ? '#e8f5e9' : '#fff3e0',
                      color: rd.scan_status === 'completed' ? '#27ae60' : '#e67e22' }}>
                      {rd.scan_status === 'completed' ? 'Baigtas' : 'Sustabdytas'}
                    </span>
                  </div>
                  <span style={{ fontSize: '0.85rem', color: '#7b8a9a' }}>{new Date(r.created_at).toLocaleString('lt-LT')}</span>
                </div>
                <ScanResults rd={rd} />
              </div>
            );
          })}
        </div>
      )}

      {scheduledProfiles.length > 0 && (
        <div style={{ marginTop: '32px' }}>
          <h3 style={{ color: '#1a1f36', marginBottom: '16px' }}>Automatizuoti skenavimai</h3>
          <div style={{ background: '#fff', borderRadius: '16px', overflow: 'hidden', boxShadow: '0 4px 20px rgba(38,53,92,0.05)' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ background: '#f4f7fb' }}>
                  <th style={{ padding: '12px 16px', textAlign: 'left', color: '#5c6d85', fontWeight: 600, fontSize: '0.88rem' }}>Profilis</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', color: '#5c6d85', fontWeight: 600, fontSize: '0.88rem' }}>Tikslas</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', color: '#5c6d85', fontWeight: 600, fontSize: '0.88rem' }}>Tvarkaraštis</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', color: '#5c6d85', fontWeight: 600, fontSize: '0.88rem' }}>Kitas paleidimas</th>
                  <th style={{ padding: '12px 16px' }}></th>
                </tr>
              </thead>
              <tbody>
                {scheduledProfiles.map((p, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid #f0f4fa' }}>
                    <td style={{ padding: '12px 16px', fontWeight: 600, color: '#1a1f36' }}>{p.name}</td>
                    <td style={{ padding: '12px 16px', color: '#5c6d85' }}>{p.target_ip}</td>
                    <td style={{ padding: '12px 16px', color: '#1f77d0' }}>
                      {scheduleLabel(p.schedule)}
                      {p.schedule !== 'hourly' && ` ${p.schedule === 'weekly' ? weekdayLabel(p.schedule_weekday) + ' ' : ''}${p.schedule_time}`}
                    </td>
                    <td style={{ padding: '12px 16px', color: '#7b8a9a', fontSize: '0.9rem' }}>
                      {p.next_run_at ? new Date(p.next_run_at).toLocaleString('lt-LT') : '—'}
                    </td>
                    <td style={{ padding: '12px 16px', textAlign: 'center' }}>
                      <button onClick={async () => {
                        await fetch(`${API_BASE}/profiles/${p.id}/cancel-schedule/`, { method: 'POST', headers: authHeaders });
                        setScheduledProfiles(prev => prev.filter(x => x.id !== p.id));
                      }} style={{ padding: '6px 12px', borderRadius: '8px', border: '1px solid #e74c3c', background: '#fff', color: '#e74c3c', cursor: 'pointer', fontSize: '0.85rem', fontWeight: 600 }}>
                        Panaikinti
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function IstorijaTab({ authHeaders, onViewResult }) {
  const [history, setHistory] = useState([]);
  const [selected, setSelected] = useState(null);
  const [compareIds, setCompareIds] = useState([]);
  const [comparing, setComparing] = useState(false);
  const [filterIp, setFilterIp] = useState('');
  const [filterPort, setFilterPort] = useState('');
  const [filterCve, setFilterCve] = useState('all');

  useEffect(() => {
    fetch(`${API_BASE}/results/`, { headers: authHeaders })
      .then(r => r.json())
      .then(d => setHistory(d.results || []));
  }, []);

  const severityLabel = (s) => s >= 7 ? 'Aukštas' : s >= 4 ? 'Vidutinis' : s > 0 ? 'Žemas' : 'Info';
  const severityColor = (s) => s >= 7 ? '#c0392b' : s >= 4 ? '#e67e22' : s > 0 ? '#27ae60' : '#7b8a9a';

  if (comparing && compareIds.length === 2) {
    const a = history.find(r => r.id === compareIds[0]);
    const b = history.find(r => r.id === compareIds[1]);
    const rdA = a?.report_data || {};
    const rdB = b?.report_data || {};
    const portsA = new Set((rdA.hosts||[]).flatMap(h=>(h.ports||[]).filter(p=>p.state==='open').map(p=>p.port)));
    const portsB = new Set((rdB.hosts||[]).flatMap(h=>(h.ports||[]).filter(p=>p.state==='open').map(p=>p.port)));
    const newPorts = [...portsB].filter(p => !portsA.has(p));
    const closedPorts = [...portsA].filter(p => !portsB.has(p));
    const cvesA = new Set((rdA.openvas?.vulnerabilities||[]).flatMap(v=>v.cves||[]));
    const cvesB = new Set((rdB.openvas?.vulnerabilities||[]).flatMap(v=>v.cves||[]));
    const newCves = [...cvesB].filter(c => !cvesA.has(c));
    const fixedCves = [...cvesA].filter(c => !cvesB.has(c));
    const samePortCount = [...portsA].filter(p => portsB.has(p)).length;

    return (
      <div>
        <button onClick={() => { setComparing(false); setCompareIds([]); }}
          style={{ marginBottom: '20px', padding: '8px 16px', borderRadius: '8px', border: '1px solid #d7dceb', background: '#fff', cursor: 'pointer' }}>
          ← Atgal
        </button>
        <h2 style={{ color: '#1a1f36', marginBottom: '20px' }}>Skenavimų palyginimas</h2>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '20px' }}>
          {[{r: a, label: 'A'}, {r: b, label: 'B'}].map(({r, label}) => (
            <div key={label} style={{ padding: '16px', borderRadius: '14px', background: '#fff', border: '1px solid #d7dceb' }}>
              <strong style={{ color: '#1f77d0' }}>{label}</strong>
              <div style={{ color: '#1a1f36', fontWeight: 600 }}>{r?.report_data?.target}</div>
              <div style={{ color: '#7b8a9a', fontSize: '0.85rem' }}>{new Date(r?.created_at).toLocaleString('lt-LT')}</div>
              <div style={{ fontSize: '0.85rem', marginTop: '4px' }}>Portų: {label === 'A' ? portsA.size : portsB.size} · CVE: {label === 'A' ? cvesA.size : cvesB.size}</div>
            </div>
          ))}
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: '12px', marginBottom: '24px' }}>
          {[
            { label: 'Nauji portai', items: newPorts, color: '#e74c3c', bg: '#fde8e8' },
            { label: 'Uždaryti portai', items: closedPorts, color: '#27ae60', bg: '#e8f5e9' },
            { label: 'Nauji CVE', items: newCves, color: '#e74c3c', bg: '#fde8e8' },
            { label: 'Išspręsti CVE', items: fixedCves, color: '#27ae60', bg: '#e8f5e9' },
          ].map(({label, items, color, bg}) => (
            <div key={label} style={{ padding: '16px', borderRadius: '14px', background: bg }}>
              <div style={{ fontWeight: 700, color, marginBottom: '8px' }}>{label} ({items.length})</div>
              {items.length === 0 ? <div style={{ color: '#7b8a9a', fontSize: '0.85rem' }}>Nėra</div>
                : items.map(i => <div key={i} style={{ fontSize: '0.85rem', color: '#1a1f36', marginBottom: '2px' }}>{i}</div>)}
            </div>
          ))}
        </div>
        <div style={{ padding: '16px', borderRadius: '14px', background: '#f4f7fb', color: '#5c6d85', fontSize: '0.9rem' }}>
          Sutampantys portai: <strong>{samePortCount}</strong>
        </div>
      </div>
    );
  }

  if (selected) {
    const rd = selected.report_data || {};
    return (
      <div>
        <button onClick={() => setSelected(null)} style={{ marginBottom: '20px', padding: '8px 16px', borderRadius: '8px', border: '1px solid #d7dceb', background: '#fff', cursor: 'pointer' }}>
          ← Atgal
        </button>
        <div style={{ padding: '24px', borderRadius: '20px', background: '#fff', boxShadow: '0 18px 60px rgba(38,53,92,0.05)' }}>
          <h3 style={{ color: '#1a1f36', marginBottom: '4px' }}>{rd.target}</h3>
          <p style={{ color: '#7b8a9a', fontSize: '0.9rem', marginBottom: '20px' }}>{new Date(selected.created_at).toLocaleString('lt-LT')}</p>
          <ScanResults rd={rd} />
        </div>
      </div>
    );
  }

  const allPorts = [...new Set(
    history.flatMap(r => (r.report_data?.hosts || [])
      .flatMap(h => (h.ports || []).filter(p => p.state === 'open').map(p => ({ port: p.port, service: p.service })))
    ).map(p => JSON.stringify(p))
  )].map(s => JSON.parse(s)).sort((a, b) => a.port - b.port);

  const filtered = history.filter(r => {
    const rd = r.report_data || {};
    if (filterIp && !(rd.target || '').includes(filterIp)) return false;
    if (filterPort) {
      const port = parseInt(filterPort);
      const hasPort = (rd.hosts || []).some(h => (h.ports || []).some(p => p.port === port && p.state === 'open'));
      if (!hasPort) return false;
    }
    if (filterCve === 'with') {
      const hasCve = (rd.openvas?.vulnerabilities || []).some(v => v.cves && v.cves.length > 0);
      if (!hasCve) return false;
    }
    if (filterCve === 'without') {
      const hasCve = (rd.openvas?.vulnerabilities || []).some(v => v.cves && v.cves.length > 0);
      if (hasCve) return false;
    }
    return true;
  });

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <h2 style={{ color: '#1a1f36', margin: 0 }}>Skenavimų istorija</h2>
        {compareIds.length === 2 && (
          <button onClick={() => setComparing(true)}
            style={{ padding: '8px 20px', borderRadius: '10px', border: 'none', background: '#1f77d0', color: '#fff', fontWeight: 700, cursor: 'pointer' }}>
            Palyginti ({compareIds.length}/2)
          </button>
        )}
        {compareIds.length === 1 && (
          <span style={{ color: '#7b8a9a', fontSize: '0.9rem' }}>Pasirinkite dar vieną palyginimui</span>
        )}
      </div>
      <div style={{ display: 'flex', gap: '12px', marginBottom: '20px', flexWrap: 'wrap' }}>
        <input value={filterIp} onChange={e => setFilterIp(e.target.value)} placeholder="Filtruoti pagal IP..."
          style={{ padding: '10px 14px', borderRadius: '12px', border: '1px solid #d7dceb', background: '#fff', fontSize: '0.9rem', minWidth: '180px' }} />
        <select value={filterPort} onChange={e => setFilterPort(e.target.value)}
          style={{ padding: '10px 14px', borderRadius: '12px', border: '1px solid #d7dceb', background: '#fff', fontSize: '0.9rem', minWidth: '160px' }}>
          <option value="">Visi portai</option>
          {allPorts.map(({port, service}) => (
            <option key={port} value={port}>{port} — {service}</option>
          ))}
        </select>
        <select value={filterCve} onChange={e => setFilterCve(e.target.value)}
          style={{ padding: '10px 14px', borderRadius: '12px', border: '1px solid #d7dceb', background: '#fff', fontSize: '0.9rem' }}>
          <option value="all">Visi CVE</option>
          <option value="with">Su CVE</option>
          <option value="without">Be CVE</option>
        </select>
        {(filterIp || filterPort || filterCve !== 'all') && (
          <button onClick={() => { setFilterIp(''); setFilterPort(''); setFilterCve('all'); }}
            style={{ padding: '10px 14px', borderRadius: '12px', border: '1px solid #d7dceb', background: '#fff', cursor: 'pointer', color: '#e74c3c', fontSize: '0.9rem' }}>
            Išvalyti
          </button>
        )}
      </div>
      {filtered.length === 0 ? (
        <div style={{ padding: '28px', borderRadius: '20px', background: '#fff', textAlign: 'center', color: '#6f7b8a' }}>Nėra skenavimų.</div>
      ) : (
        <div style={{ background: '#fff', borderRadius: '20px', overflow: 'hidden', boxShadow: '0 18px 60px rgba(38,53,92,0.05)' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead><tr style={{ background: '#f4f7fb', color: '#1f2d3d' }}>
              <th style={{ padding: '14px 16px', width: '40px' }}></th>
              <th style={{ padding: '14px 16px', textAlign: 'left' }}>Tikslas</th>
              <th style={{ padding: '14px 16px', textAlign: 'left' }}>Data</th>
              <th style={{ padding: '14px 16px', textAlign: 'left' }}>Portai</th>
              <th style={{ padding: '14px 16px', textAlign: 'left' }}>OpenVAS</th>
              <th style={{ padding: '14px 16px', textAlign: 'left' }}>Statusas</th>
              <th style={{ padding: '14px 16px' }}></th>
            </tr></thead>
            <tbody>{filtered.map((r, i) => {
              const rd = r.report_data || {};
              const openPorts = (rd.hosts || []).reduce((s, h) => s + (h.open_port_count || 0), 0);
              const vulnCount = rd.openvas?.vulnerabilities?.length || 0;
              const duration = rd.duration_seconds != null ? `${Math.floor(rd.duration_seconds/60)}m ${rd.duration_seconds%60}s` : '—';
              const isChecked = compareIds.includes(r.id);
              return (
                <tr key={i} style={{ borderBottom: '1px solid #f0f4fa', background: isChecked ? '#eef4ff' : 'transparent' }}>
                  <td style={{ padding: '12px 16px', textAlign: 'center' }}>
                    <input type="checkbox" checked={isChecked}
                      onChange={e => {
                        if (e.target.checked) { if (compareIds.length < 2) setCompareIds(prev => [...prev, r.id]); }
                        else setCompareIds(prev => prev.filter(x => x !== r.id));
                      }} style={{ cursor: 'pointer' }} />
                  </td>
                  <td style={{ padding: '12px 16px', fontWeight: 600 }}>{rd.target || '—'}</td>
                  <td style={{ padding: '12px 16px', color: '#7b8a9a', fontSize: '0.85rem' }}>
                    <div>Pradeta: {new Date(rd.started_at || r.created_at).toLocaleString('lt-LT')}</div>
                    {rd.completed_at && <div>Baigta: {new Date(rd.completed_at).toLocaleString('lt-LT')}</div>}
                    <div style={{ color: '#1f77d0' }}>Trukme: {duration}</div>
                  </td>
                  <td style={{ padding: '12px 16px' }}>{openPorts}</td>
                  <td style={{ padding: '12px 16px' }}>{vulnCount} radinių</td>
                  <td style={{ padding: '12px 16px' }}>
                    <span style={{ padding: '3px 10px', borderRadius: '8px', fontSize: '0.85rem', fontWeight: 600,
                      background: rd.scan_status === 'completed' ? '#e8f5e9' : rd.scan_status === 'stopped' ? '#fde8e8' : '#fff3e0',
                      color: rd.scan_status === 'completed' ? '#27ae60' : rd.scan_status === 'stopped' ? '#c0392b' : '#e67e22' }}>
                      {rd.scan_status === 'completed' ? 'Baigtas' : rd.scan_status === 'stopped' ? 'Sustabdytas' : 'Vykdomas'}
                    </span>
                  </td>
                  <td style={{ padding: '12px 16px', textAlign: 'center' }}>
                    <button onClick={() => setSelected(r)} style={{ padding: '6px 14px', borderRadius: '8px', border: '1px solid #d7dceb', background: '#fff', cursor: 'pointer', color: '#1f77d0', fontWeight: 600 }}>
                      Peržiūrėti
                    </button>
                  </td>
                </tr>
              );
            })}</tbody>
          </table>
        </div>
      )}
    </div>
  );
}

const NAV_TABS = [
  { id: 'profiliai', label: 'Skenavimo profiliai' },
  { id: 'vykdymas', label: 'Vykdymas' },
  { id: 'istorija', label: 'Istorija' },
  { id: 'profilis', label: 'Profilis' },
];

function Navbar({ activeTab, setActiveTab, onLogout }) {
  return (
    <nav style={{ background: '#1a1f36', padding: '0 36px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', position: 'sticky', top: 0, zIndex: 100 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
        <span style={{ color: '#4780d0', fontWeight: 700, marginRight: '24px', fontSize: '1rem' }}>Tinklo Saugumo Skeneris</span>
        {NAV_TABS.map(tab => (
          <button key={tab.id} onClick={() => setActiveTab(tab.id)}
            style={{ padding: '18px 20px', background: 'none', border: 'none', cursor: 'pointer', fontSize: '0.95rem', fontWeight: activeTab === tab.id ? 700 : 400,
              color: activeTab === tab.id ? '#fff' : '#8a9ab5', borderBottom: activeTab === tab.id ? '3px solid #4780d0' : '3px solid transparent' }}>
            {tab.label}
          </button>
        ))}
      </div>
      <button onClick={onLogout} style={{ padding: '8px 16px', borderRadius: '8px', border: '1px solid #2d3555', background: 'none', color: '#8a9ab5', cursor: 'pointer', fontSize: '0.9rem' }}>
        Atsijungti
      </button>
    </nav>
  );
}

function ProfilisTab({ authHeaders, onLogout }) {
  const [userData, setUserData] = useState(null);
  const [email, setEmail] = useState('');
  const [msg, setMsg] = useState('');
  const [showEmailPrompt, setShowEmailPrompt] = useState(false);

  useEffect(() => {
    fetch(`${API_BASE}/user-profile/`, { headers: authHeaders })
      .then(r => r.json())
      .then(d => {
        setUserData(d);
        setEmail(d.email || '');
        if (!d.email) setShowEmailPrompt(true);
      });
  }, []);

  const handleSave = async (e) => {
    e.preventDefault();
    const res = await fetch(`${API_BASE}/user-profile/`, {
      method: 'POST', headers: authHeaders,
      body: JSON.stringify({ email }),
    });
    const d = await res.json();
    if (d.status === 'ok') {
      setMsg('El. paštas išsaugotas.');
      setShowEmailPrompt(false);
      setUserData(prev => ({ ...prev, email }));
    }
  };

  const inputStyle = { width: '100%', padding: '12px 16px', borderRadius: '12px', border: '1px solid #d7dceb', fontSize: '0.98rem', boxSizing: 'border-box', marginBottom: '12px' };

  return (
    <div style={{ maxWidth: '420px' }}>
      {showEmailPrompt && (
        <div style={{ padding: '16px 20px', borderRadius: '14px', background: '#fff3e0', border: '1px solid #e0c88a', marginBottom: '20px', color: '#7a4f00' }}>
          ⚠️ El. paštas nenurodytas — negalėsite atkurti slaptažodžio. Nurodykite žemiau.
        </div>
      )}
      <div style={{ padding: '28px', borderRadius: '20px', background: '#fff', boxShadow: '0 20px 68px rgba(38,53,92,0.06)' }}>
        <h2 style={{ color: '#1a1f36', marginBottom: '20px' }}>Profilis</h2>
        {userData && <p style={{ color: '#5c6d85', marginBottom: '20px' }}>Prisijungęs kaip <strong>{userData.username}</strong></p>}
        <form onSubmit={handleSave}>
          <label style={{ display: 'block', marginBottom: '8px', color: '#5c6d85', fontWeight: 600 }}>El. paštas (slaptažodžio atkūrimui)</label>
          <input type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="pvz. vardas@gmail.com" style={inputStyle} />
          {msg && <p style={{ color: '#27ae60', marginBottom: '12px', fontSize: '0.9rem' }}>{msg}</p>}
          <button type="submit" style={{ width: '100%', padding: '13px', borderRadius: '12px', border: 'none', background: '#1f77d0', color: '#fff', fontWeight: 700, cursor: 'pointer', marginBottom: '16px' }}>
            Išsaugoti
          </button>
        </form>
        <button onClick={onLogout} style={{ width: '100%', padding: '13px', borderRadius: '12px', border: 'none', background: '#e74c3c', color: '#fff', fontWeight: 700, cursor: 'pointer' }}>
          Atsijungti
        </button>
      </div>
    </div>
  );
}

function App() {
  const [token, setToken] = useState(localStorage.getItem('auth_token'));
  const [activeTab, setActiveTab] = useState('profiliai');
  const [target, setTarget] = useState('');
  const [profileName, setProfileName] = useState('Greitas profilio skenavimas');
  const [intensity, setIntensity] = useState('medium');
  const [profiles, setProfiles] = useState([]);
  const [selectedProfileId, setSelectedProfileId] = useState(null);
  const [selectedProfile, setSelectedProfile] = useState(null);
  const [checkedProfiles, setCheckedProfiles] = useState([]);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState({ hosts: [], openvas: {} });
  const [statusMessage, setStatusMessage] = useState('Pasirinkite profilio skenavimui arba sukurkite naują.');
  const [scanMode, setScanMode] = useState('single');
  const [useOpenvas, setUseOpenvas] = useState(true);
  const [nmapVersionScan, setNmapVersionScan] = useState(false);
  const [openvasConfig, setOpenvasConfig] = useState('base');
  const [schedule, setSchedule] = useState('none');
  const [scheduleTime, setScheduleTime] = useState('08:00');
  const [scheduleWeekday, setScheduleWeekday] = useState(0);
  const [runNow, setRunNow] = useState(true);

  const authHeaders = { 'Authorization': `Token ${token}`, 'Content-Type': 'application/json' };

  const handleLogout = () => { localStorage.removeItem('auth_token'); setToken(null); };

  const fetchProfiles = async () => {
    try {
      const response = await fetch(`${API_BASE}/profiles/`, { headers: authHeaders });
      if (response.status === 401) { localStorage.removeItem('auth_token'); setToken(null); return; }
      const data = await response.json();
      setProfiles(data.profiles || []);
    } catch (err) {
      console.error('Unable to load profiles', err);
    }
  };

  const fetchLatestResults = async (profileId) => {
    if (!profileId) return;
    try {
      const response = await fetch(`${API_BASE}/profiles/${profileId}/results/latest/`, { headers: authHeaders });
      const data = await response.json();
      const reportData = data.report_data || (data.results && data.results.length > 0 ? data.results[0].report_data : null);
      if (reportData) {
        setResults(reportData);
        if (reportData.scan_status === 'running') {
          setStatusMessage('Skenavimas vykdomas...');
        } else {
          setStatusMessage('Paskutiniai rezultatai gauti.');
          setLoading(false);
        }
        return reportData;
      }
    } catch (err) {
      console.error('Failed to fetch results', err);
    }
  };

  useEffect(() => {
    fetchProfiles();
  }, []);

  useEffect(() => {
    let interval;
    if (loading && selectedProfileId) {
      interval = setInterval(() => fetchLatestResults(selectedProfileId), 3000);
    }
    return () => clearInterval(interval);
  }, [loading, selectedProfileId]);

  const handleProfileSelect = (event) => {
    const profileId = event.target.value;
    setSelectedProfileId(profileId || null);
    const profile = profiles.find((profile) => String(profile.id) === String(profileId));
    setSelectedProfile(profile || null);
    if (profile) {
      setTarget(profile.target_ip);
      setIntensity(profile.intensity);
      setScanMode(profile.target_ip.includes('-') || profile.target_ip.includes('/') ? 'range' : 'single');
      fetchLatestResults(profile.id);
    }
  };

  const handleSaveProfile = async () => {
    if (!target) { setStatusMessage('Įveskite tikslinį IP adresą ar intervalą.'); return; }
    setStatusMessage('Saugomas profilis...');
    try {
      const response = await fetch(`${API_BASE}/profiles/create/`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({ name: profileName, target_ip: target, intensity, use_openvas: useOpenvas, nmap_version_scan: nmapVersionScan, openvas_config: openvasConfig, schedule, schedule_time: scheduleTime, schedule_weekday: scheduleWeekday }),
      });
      const profileResponse = await response.json();
      if (!response.ok) { setStatusMessage(profileResponse.message || 'Nepavyko sukurti profilio.'); return; }
      setProfiles((prev) => [profileResponse.profile, ...prev]);
      setStatusMessage('Profilis išsaugotas.');
      setProfileName('Greitas profilio skenavimas');
      setTarget('');
    } catch (err) {
      setStatusMessage('Klaida išsaugant profilį.');
    }
  };

  const handleStartScanWithProfile = async (profileId) => {
    setSelectedProfileId(profileId);
    const profile = profiles.find(p => p.id === profileId);
    setSelectedProfile(profile);
    setLoading(true);
    setResults({ hosts: [], openvas: {} });

    try {
      await fetch(`${API_BASE}/profiles/${profileId}/scan/`, { method: 'POST', headers: authHeaders });
      setActiveTab('vykdymas');
      setStatusMessage('Skenavimas pradėtas. Laukiama rezultatų...');
      
      // Poll for results - keep polling for up to 5 minutes
      let pollCount = 0;
      const maxPolls = 700; // 700 × 3s = 35 min
      const pollInterval = setInterval(async () => {
        pollCount++;
        try {
          const result = await fetchLatestResults(profileId);
          if (result && result.scan_status === 'completed') {
            clearInterval(pollInterval);
            setLoading(false);
            setStatusMessage('Skenavimas baigtas! Rezultatai rodyti žemiau.');
          }
        } catch (err) {
          console.error('Poll error:', err);
        }
        
        if (pollCount >= maxPolls) {
          clearInterval(pollInterval);
          setLoading(false);
          setStatusMessage('Skenavimo laikas baigėsi. Jei rezultatai dar neparodyti, jie gali būti dar apdorojami.');
        }
      }, 3000);
    } catch (err) {
      console.error(err);
      setStatusMessage('Klaida pradėjus skenavimą.');
      setLoading(false);
    }
  };

  const renderPortRows = (ports) => {
    if (!ports || ports.length === 0) {
      return (
        <tr>
          <td colSpan="4" style={{ padding: '14px', textAlign: 'center' }}>
            Nėra atidengtų portų.
          </td>
        </tr>
      );
    }

    return ports.map((portInfo) => (
      <tr key={`${portInfo.port}-${portInfo.service}`}>
        <td style={{ padding: '10px', textAlign: 'center' }}>{portInfo.port}</td>
        <td style={{ padding: '10px' }}>{portInfo.service}</td>
        <td style={{ padding: '10px', color: portInfo.state === 'open' ? '#116a0d' : '#a00' }}>
          {portInfo.state}
        </td>
        <td style={{ padding: '10px' }}>{portInfo.vulnerability}</td>
      </tr>
    ));
  };

  const totalHosts = results.hosts ? results.hosts.length : 0;
  const totalOpenPorts = results.hosts
    ? results.hosts.reduce((sum, host) => sum + (host.open_port_count || 0), 0)
    : 0;

  if (!token) return <LoginForm onLogin={setToken} />;

  return (
    <div style={{ fontFamily: 'Inter, Arial, sans-serif', background: '#f4f7fb', minHeight: '100vh', zoom: '75%' }}>
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} onLogout={handleLogout} />
      <div style={{ padding: '24px 32px', maxWidth: '1180px', margin: '0 auto' }}>

      {activeTab === 'profiliai' && <div>
      <div style={{ display: 'grid', gap: '24px', gridTemplateColumns: '1.5fr 1fr', marginBottom: '28px' }}>
        <div style={{ padding: '28px', borderRadius: '24px', background: '#ffffff', boxShadow: '0 20px 68px rgba(38, 53, 92, 0.06)' }}>
          <h2 style={{ marginBottom: '18px', color: '#1a1f36' }}>Naujas skenavimo profilis</h2>
          <div style={{ display: 'grid', gap: '18px' }}>
            <div>
              <label style={{ display: 'block', marginBottom: '8px', color: '#5c6d85', fontWeight: 600 }}>Profilio pavadinimas</label>
              <input
                value={profileName}
                onChange={(e) => setProfileName(e.target.value)}
                placeholder="Pvz. Naktinis skenavimas"
                style={{ width: '100%', padding: '14px 16px', borderRadius: '16px', border: '1px solid #d7dceb', background: '#fafbfc', fontSize: '0.98rem', boxSizing: 'border-box' }}
              />
            </div>

            <div>
              <label style={{ display: 'block', marginBottom: '8px', color: '#5c6d85', fontWeight: 600 }}>Skenerio režimas</label>
              <div style={{ display: 'flex', gap: '10px' }}>
                <button
                  type="button"
                  onClick={() => setScanMode('single')}
                  style={{ flex: 1, padding: '12px 0', borderRadius: '12px', border: scanMode === 'single' ? '1px solid #1f77d0' : '1px solid #d7dceb', background: scanMode === 'single' ? '#eef4ff' : '#fff', color: scanMode === 'single' ? '#1f77d0' : '#5c6d85', cursor: 'pointer' }}
                >
                  Vienas IP
                </button>
                <button
                  type="button"
                  onClick={() => setScanMode('range')}
                  style={{ flex: 1, padding: '12px 0', borderRadius: '12px', border: scanMode === 'range' ? '1px solid #1f77d0' : '1px solid #d7dceb', background: scanMode === 'range' ? '#eef4ff' : '#fff', color: scanMode === 'range' ? '#1f77d0' : '#5c6d85', cursor: 'pointer' }}
                >
                  IP intervalas
                </button>
              </div>
            </div>

            <div>
              <label style={{ display: 'block', marginBottom: '8px', color: '#5c6d85', fontWeight: 600 }}>{scanMode === 'range' ? 'IP intervalas arba CIDR' : 'Taikinio IP / domenas'}</label>
              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder={scanMode === 'range' ? 'pvz. 192.168.1.1-192.168.1.20 arba 192.168.1.0/24' : 'pvz. scanme.nmap.org'}
                style={{ width: '100%', padding: '14px 16px', borderRadius: '16px', border: '1px solid #d7dceb', background: '#fafbfc', fontSize: '0.98rem', boxSizing: 'border-box' }}
              />
              <p style={{ marginTop: '10px', color: '#7b8a9a', fontSize: '0.95rem' }}>
                {scanMode === 'range'
                  ? 'Nurodykite IP intervalą arba CIDR, kad Nmap skenuotų kelis taikinius.'
                  : 'Skeneris palaiko vieną IP adresą arba FQDN.'}
              </p>
            </div>

            <div>
              <label style={{ display: 'block', marginBottom: '8px', color: '#5c6d85', fontWeight: 600 }}>Skenavimo intensyvumas</label>
              <select
                value={intensity}
                onChange={(e) => setIntensity(e.target.value)}
                style={{ width: '100%', padding: '14px 16px', borderRadius: '16px', border: '1px solid #d7dceb', background: '#fafbfc', fontSize: '0.98rem' }}
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
              </select>
            </div>

            <div>
              <label style={{ display: 'block', marginBottom: '8px', color: '#5c6d85', fontWeight: 600 }}>Nmap versijų skenavimas (-sV)</label>
              <div style={{ display: 'flex', gap: '10px' }}>
                {[{v: false, l: 'Išjungtas (greičiau)'}, {v: true, l: 'Įjungtas (lėčiau)'}].map(({v, l}) => (
                  <button key={String(v)} type="button" onClick={() => setNmapVersionScan(v)}
                    style={{ flex: 1, padding: '12px 0', borderRadius: '12px', border: nmapVersionScan === v ? '1px solid #1f77d0' : '1px solid #d7dceb', background: nmapVersionScan === v ? '#eef4ff' : '#fff', color: nmapVersionScan === v ? '#1f77d0' : '#5c6d85', cursor: 'pointer', fontSize: '0.9rem' }}>
                    {l}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label style={{ display: 'block', marginBottom: '8px', color: '#5c6d85', fontWeight: 600 }}>OpenVAS</label>
              <div style={{ display: 'flex', gap: '10px', marginBottom: '10px' }}>
                {[{v: true, l: 'Įjungtas'}, {v: false, l: 'Išjungtas (tik Nmap)'}].map(({v, l}) => (
                  <button key={String(v)} type="button" onClick={() => setUseOpenvas(v)}
                    style={{ flex: 1, padding: '12px 0', borderRadius: '12px', border: useOpenvas === v ? '1px solid #1f77d0' : '1px solid #d7dceb', background: useOpenvas === v ? '#eef4ff' : '#fff', color: useOpenvas === v ? '#1f77d0' : '#5c6d85', cursor: 'pointer', fontSize: '0.9rem' }}>
                    {l}
                  </button>
                ))}
              </div>
              {useOpenvas && (
                <select value={openvasConfig} onChange={(e) => setOpenvasConfig(e.target.value)}
                  style={{ width: '100%', padding: '14px 16px', borderRadius: '16px', border: '1px solid #d7dceb', background: '#fafbfc', fontSize: '0.98rem' }}>
                  <option value="base">Base (rekomenduojama)</option>
                  <option value="discovery">Discovery (greičiausias)</option>
                  <option value="full_and_fast">Full and fast (lėčiausias, daugiausiai CVE)</option>
                </select>
              )}
            </div>

            <div>
              <label style={{ display: 'block', marginBottom: '8px', color: '#5c6d85', fontWeight: 600 }}>Automatinis tvarkaraštis</label>
              <select value={schedule} onChange={e => setSchedule(e.target.value)}
                style={{ width: '100%', padding: '14px 16px', borderRadius: '16px', border: '1px solid #d7dceb', background: '#fafbfc', fontSize: '0.98rem', marginBottom: '10px' }}>
                <option value="none">Nėra (tik rankinis)</option>
                <option value="hourly">Kas valandą</option>
                <option value="daily">Kas dieną</option>
                <option value="weekly">Kas savaitę</option>
              </select>
              {schedule !== 'none' && (
                <div style={{ display: 'flex', gap: '10px' }}>
                  {schedule === 'weekly' && (
                    <select value={scheduleWeekday} onChange={e => setScheduleWeekday(Number(e.target.value))}
                      style={{ flex: 1, padding: '12px 14px', borderRadius: '12px', border: '1px solid #d7dceb', background: '#fff', fontSize: '0.9rem' }}>
                      {['Pirmadienis','Antradienis','Trečiadienis','Ketvirtadienis','Penktadienis','Šeštadienis','Sekmadienis'].map((d,i) => (
                        <option key={i} value={i}>{d}</option>
                      ))}
                    </select>
                  )}
                  {schedule !== 'hourly' && (
                    <div style={{ display: 'flex', gap: '6px', alignItems: 'center', flex: 1 }}>
                      <select value={scheduleTime.split(':')[0]} onChange={e => setScheduleTime(`${e.target.value}:${scheduleTime.split(':')[1]}`)}
                        style={{ flex: 1, padding: '12px 8px', borderRadius: '12px', border: '1px solid #d7dceb', background: '#fff', fontSize: '0.9rem' }}>
                        {Array.from({length: 24}, (_, i) => String(i).padStart(2,'0')).map(h => <option key={h} value={h}>{h}</option>)}
                      </select>
                      <span style={{ color: '#5c6d85', fontWeight: 700 }}>:</span>
                      <select value={scheduleTime.split(':')[1]} onChange={e => setScheduleTime(`${scheduleTime.split(':')[0]}:${e.target.value}`)}
                        style={{ flex: 1, padding: '12px 8px', borderRadius: '12px', border: '1px solid #d7dceb', background: '#fff', fontSize: '0.9rem' }}>
                        {['00','15','30','45'].map(m => <option key={m} value={m}>{m}</option>)}
                      </select>
                    </div>
                  )}
                </div>
              )}
            </div>

            <button
              onClick={handleSaveProfile}
              style={{ width: '100%', padding: '16px', borderRadius: '16px', border: 'none', background: '#1f77d0', color: '#fff', fontWeight: '700', fontSize: '1rem', cursor: 'pointer' }}
            >
              Issaugoti profili
            </button>
          </div>
        </div>

        <aside style={{ display: 'grid', gap: '20px' }}>
          <div style={{ padding: '24px', borderRadius: '24px', background: '#1f77d0', color: '#fff', boxShadow: '0 20px 42px rgba(31, 117, 208, 0.14)' }}>
            <h3 style={{ marginBottom: '12px' }}>Skenavimo santrauka</h3>
            <p style={{ margin: 0, fontSize: '0.95rem', color: '#d9e6fb' }}>Paskutiniai profiliai ir paleisti skenavimai.</p>
            <div style={{ display: 'grid', gap: '12px', marginTop: '18px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Aktyvių profilių skaičius</span>
                <strong>{profiles.length}</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Atidarytų portų</span>
                <strong>{totalOpenPorts}</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Skenerio tikslinių IP</span>
                <strong>{totalHosts}</strong>
              </div>
            </div>
          </div>

          <div style={{ padding: '24px', borderRadius: '24px', background: '#ffffff', boxShadow: '0 20px 68px rgba(38, 53, 92, 0.06)' }}>
            <h3 style={{ marginBottom: '12px', color: '#1a1f36' }}>Paskutinis pasirinktas profilis</h3>
            {selectedProfile ? (
              <div style={{ color: '#475261', fontSize: '0.95rem' }}>
                <p style={{ margin: '10px 0' }}><strong>{selectedProfile.name}</strong></p>
                <p style={{ margin: '6px 0' }}>Tikslas: {selectedProfile.target_ip}</p>
                <p style={{ margin: '6px 0' }}>Intensyvumas: {selectedProfile.intensity}</p>
                {selectedProfile.schedule !== 'none' && (
                  <p style={{ margin: '6px 0', color: '#1f77d0' }}>
                    🕐 {selectedProfile.schedule === 'hourly' ? 'Kas valandą' : selectedProfile.schedule === 'daily' ? 'Kas dieną' : 'Kas savaitę'}
                    {selectedProfile.next_run_at && ` · Kitas: ${new Date(selectedProfile.next_run_at).toLocaleString('lt-LT')}`}
                  </p>
                )}
              </div>
            ) : (
              <p style={{ color: '#7b8a9a' }}>Pasirinkite arba sukurkite profilį norėdami peržiūrėti.</p>
            )}
          </div>
        </aside>
      </div>

      <section style={{ display: 'grid', gap: '24px', marginBottom: '28px' }}>
        <div style={{ background: '#fff', padding: '22px 26px', borderRadius: '20px', boxShadow: '0 20px 68px rgba(38, 53, 92, 0.06)' }}>
          <h2 style={{ marginBottom: '16px', color: '#1a1f36' }}>Skenavimo būsena</h2>
          <div style={{ padding: '18px', borderRadius: '16px', background: '#f5f8ff', border: '1px solid #dce6f5', color: '#2f4369' }}>
            <strong>Statusas:</strong> {statusMessage}
          </div>
          {results.scan_status === 'running' && (
            <div style={{ marginTop: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px', fontSize: '0.9rem', color: '#5c6d85' }}>
                <span>OpenVAS skenavimas...</span>
                <span>{results.openvas_progress || 0}%</span>
              </div>
              <div style={{ height: '10px', borderRadius: '8px', background: '#e0e7f0', overflow: 'hidden' }}>
                <div style={{
                  height: '100%', borderRadius: '8px', background: '#1f77d0',
                  width: `${results.openvas_progress || 0}%`,
                  transition: 'width 0.5s ease'
                }} />
              </div>
            </div>
          )}
        </div>

        <div style={{ display: 'grid', gap: '16px' }}>
          <div style={{ padding: '22px', borderRadius: '20px', background: '#fff', boxShadow: '0 20px 68px rgba(38, 53, 92, 0.06)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
              <h2 style={{ margin: 0, color: '#1a1f36' }}>Esami profiliai</h2>
              {checkedProfiles.length > 0 && (
                <button onClick={async () => {
                  if (!window.confirm(`Ištrinti ${checkedProfiles.length} profilį(-ius)?`)) return;
                  await Promise.all(checkedProfiles.map(id =>
                    fetch(`${API_BASE}/profiles/${id}/delete/`, { method: 'DELETE', headers: authHeaders })
                  ));
                  setProfiles(prev => prev.filter(p => !checkedProfiles.includes(p.id)));
                  if (checkedProfiles.includes(Number(selectedProfileId))) {
                    setSelectedProfileId(null); setSelectedProfile(null); setResults({ hosts: [], openvas: {} });
                  }
                  setCheckedProfiles([]);
                }} style={{ padding: '7px 14px', borderRadius: '10px', border: '1px solid #e74c3c', background: '#fff', color: '#e74c3c', cursor: 'pointer', fontSize: '0.88rem', fontWeight: 600 }}>
                  Ištrinti ({checkedProfiles.length})
                </button>
              )}
            </div>
            <div style={{ maxHeight: '320px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {profiles.length === 0 && <p style={{ color: '#7b8a9a', textAlign: 'center', padding: '20px' }}>Nera profiliu. Sukurkite nauja.</p>}
              {profiles.map((profile) => (
                <div key={profile.id} style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '12px 14px', borderRadius: '12px', border: '1px solid #e0e7f0', background: '#fafbfc' }}>
                  <input type="checkbox" checked={checkedProfiles.includes(profile.id)}
                    onChange={e => setCheckedProfiles(prev => e.target.checked ? [...prev, profile.id] : prev.filter(x => x !== profile.id))}
                    style={{ cursor: 'pointer' }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontWeight: 600, color: '#1a1f36', fontSize: '0.9rem' }}>{profile.name}</div>
                    <div style={{ color: '#7b8a9a', fontSize: '0.82rem' }}>{profile.target_ip} · {profile.intensity} · {profile.openvas_config}</div>
                    {profile.schedule !== 'none' && <div style={{ color: '#1f77d0', fontSize: '0.8rem' }}>{profile.schedule === 'hourly' ? 'Kas valanda' : profile.schedule === 'daily' ? 'Kas diena' : 'Kas savaite'} {profile.schedule_time}</div>}
                  </div>
                  <button onClick={() => handleStartScanWithProfile(profile.id)}
                    style={{ padding: '7px 14px', borderRadius: '9px', border: 'none', background: '#1f77d0', color: '#fff', cursor: 'pointer', fontWeight: 600, fontSize: '0.85rem', whiteSpace: 'nowrap' }}>
                    Skenuoti
                  </button>
                  <button onClick={async () => {
                    if (!window.confirm('Istrinti profili?')) return;
                    await fetch(`${API_BASE}/profiles/${profile.id}/delete/`, { method: 'DELETE', headers: authHeaders });
                    setProfiles(prev => prev.filter(p => p.id !== profile.id));
                  }} style={{ padding: '7px 10px', borderRadius: '9px', border: '1px solid #e74c3c', background: '#fff', color: '#e74c3c', cursor: 'pointer', fontSize: '0.85rem' }}>
                    Trinti
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <section>
        <h2 style={{ marginBottom: '18px', color: '#1a1f36' }}>Rezultatai pagal IP / intervalą</h2>
        {results.hosts && results.hosts.length > 0 ? (
          results.hosts.map((host) => (
            <div key={host.ip} style={{ marginBottom: '28px', padding: '24px', borderRadius: '20px', background: '#ffffff', boxShadow: '0 18px 60px rgba(38, 53, 92, 0.05)' }}>
              <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', gap: '16px', marginBottom: '18px' }}>
                <div>
                  <p style={{ margin: 0, color: '#7b8a9a', fontSize: '0.88rem' }}>Tikslinis taikinys</p>
                  <h3 style={{ margin: '8px 0 0', color: '#1a1f36' }}>{host.ip}</h3>
                </div>
                <div style={{ display: 'flex', gap: '18px', alignItems: 'center' }}>
                  <div style={{ textAlign: 'right' }}>
                    <p style={{ margin: 0, color: '#7b8a9a', fontSize: '0.88rem' }}>Atidaryti portai</p>
                    <strong style={{ display: 'block', marginTop: '6px', color: '#1f77d0' }}>{host.open_port_count}</strong>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <p style={{ margin: 0, color: '#7b8a9a', fontSize: '0.88rem' }}>OpenVAS</p>
                    <strong style={{ display: 'block', marginTop: '6px', color: '#1f77d0' }}>{results.openvas?.status || 'Nepradėta'}</strong>
                  </div>
                </div>
              </div>

              <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: '720px' }}>
                <thead>
                  <tr style={{ background: '#f4f7fb', color: '#1f2d3d' }}>
                    <th style={{ padding: '14px 16px', borderBottom: '1px solid #e8eef7', textAlign: 'left' }}>Portas</th>
                    <th style={{ padding: '14px 16px', borderBottom: '1px solid #e8eef7', textAlign: 'left' }}>Servisas</th>
                    <th style={{ padding: '14px 16px', borderBottom: '1px solid #e8eef7', textAlign: 'left' }}>Būsena</th>
                    <th style={{ padding: '14px 16px', borderBottom: '1px solid #e8eef7', textAlign: 'left' }}>Rizika</th>
                  </tr>
                </thead>
                <tbody>{renderPortRows(host.ports)}</tbody>
              </table>

              {results.openvas?.vulnerabilities?.length > 0 && (
                <div style={{ marginTop: '24px' }}>
                  <h4 style={{ color: '#1a1f36', marginBottom: '12px' }}>OpenVAS rezultatai ({results.openvas.vulnerabilities.length})</h4>
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr style={{ background: '#fff8f0', color: '#1f2d3d' }}>
                        <th style={{ padding: '12px 16px', borderBottom: '1px solid #e8eef7', textAlign: 'left' }}>Pavadinimas</th>
                        <th style={{ padding: '12px 16px', borderBottom: '1px solid #e8eef7', textAlign: 'left', width: '90px' }}>Portas</th>
                        <th style={{ padding: '12px 16px', borderBottom: '1px solid #e8eef7', textAlign: 'left' }}>CVE</th>
                        <th style={{ padding: '12px 16px', borderBottom: '1px solid #e8eef7', textAlign: 'left', width: '130px' }}>Sunkumas</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Array.from(new Map(results.openvas.vulnerabilities.map(v => [v.name, v])).values()).map((vuln, i) => (
                        <tr key={i} style={{ borderBottom: '1px solid #f0f4fa' }}>
                          <td style={{ padding: '10px 16px' }}>{vuln.name}</td>
                          <td style={{ padding: '10px 16px', color: '#5c6d85', fontSize: '0.9rem' }}>{vuln.port || '—'}</td>
                          <td style={{ padding: '10px 16px', fontSize: '0.85rem' }}>
                            {vuln.cves && vuln.cves.length > 0
                              ? vuln.cves.map((cve, j) => (
                                  <a key={j} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noreferrer"
                                    style={{ display: 'inline-block', marginRight: '6px', color: '#1f77d0' }}>{cve}</a>
                                ))
                              : <span style={{ color: '#aaa' }}>—</span>}
                          </td>
                          <td style={{ padding: '10px 16px' }}>
                            <span style={{
                              padding: '3px 10px', borderRadius: '8px', fontSize: '0.85rem', fontWeight: 600,
                              background: vuln.severity >= 7 ? '#fde8e8' : vuln.severity >= 4 ? '#fff3e0' : '#e8f5e9',
                              color: vuln.severity >= 7 ? '#c0392b' : vuln.severity >= 4 ? '#e67e22' : '#27ae60'
                            }}>
                              {vuln.severity >= 7 ? 'Aukštas' : vuln.severity >= 4 ? 'Vidutinis' : vuln.severity > 0 ? 'Žemas' : 'Info'} ({vuln.severity})
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          ))
        ) : (
          <div style={{ padding: '28px', borderRadius: '20px', background: '#fff', textAlign: 'center', color: '#6f7b8a', border: '1px dashed #d7dceb' }}>
            Šiuo metu nėra rezultatų. Pradėkite naują skenavimą arba pasirinkite profilį.
          </div>
        )}
      </section>
      </div>}

      {activeTab === 'istorija' && <IstorijaTab authHeaders={authHeaders} onViewResult={(r) => { setResults(r.report_data); setActiveTab('profiliai'); }} />}

      {activeTab === 'vykdymas' && <VykdymasTab authHeaders={authHeaders} />}

      {activeTab === 'profilis' && <ProfilisTab authHeaders={authHeaders} onLogout={handleLogout} />}

      </div>
    </div>
  );
}

export default App;
