/\* SAMLGuard Pro \- Modern Cybersecurity & Identity SSO Dark Theme \*/  
:root {  
  \--bg-primary: \#080c18;  
  \--bg-secondary: \#0e172a;  
  \--bg-card: \#141f36;  
  \--bg-input: \#0a1122;  
  \--border-color: \#203152;  
  \--border-active: \#6366f1;  
  \--text-main: \#f1f5f9;  
  \--text-muted: \#94a3b8;  
  \--text-dim: \#64748b;  
  \--accent-indigo: \#6366f1;  
  \--accent-sky: \#38bdf8;  
  \--accent-emerald: \#10b981;  
  \--accent-yellow: \#f59e0b;  
  \--accent-red: \#ef4444;  
  \--accent-purple: \#a855f7;  
  \--font-family: \-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;  
  \--font-mono: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace;  
}

\* {  
  box-sizing: border-box;  
  margin: 0;  
  padding: 0;  
}

body {  
  background: radial-gradient(circle at 50% 0%, \#312e81 0%, var(--bg-primary) 70%);  
  color: var(--text-main);  
  font-family: var(--font-family);  
  line-height: 1.6;  
  padding: 24px;  
  min-height: 100vh;  
}

.container {  
  max-width: 1240px;  
  margin: 0 auto;  
}

/\* Header \*/  
header {  
  display: flex;  
  justify-content: space-between;  
  align-items: center;  
  padding-bottom: 24px;  
  border-bottom: 1px solid var(--border-color);  
  margin-bottom: 28px;  
  flex-wrap: wrap;  
  gap: 16px;  
}

.logo-area {  
  display: flex;  
  align-items: center;  
  gap: 14px;  
}

.logo-icon {  
  width: 44px;  
  height: 44px;  
  background: linear-gradient(135deg, var(--accent-indigo), var(--accent-sky));  
  border-radius: 10px;  
  display: flex;  
  align-items: center;  
  justify-content: center;  
  color: \#fff;  
  font-weight: 800;  
  font-size: 18px;  
  box-shadow: 0 0 20px rgba(99, 102, 241, 0.4);  
}

.title-group h1 {  
  font-size: 22px;  
  font-weight: 700;  
  letter-spacing: \-0.5px;  
  color: \#fff;  
}

.title-group p {  
  font-size: 13px;  
  color: var(--text-muted);  
}

.header-badges {  
  display: flex;  
  gap: 10px;  
}

.badge {  
  padding: 4px 10px;  
  border-radius: 6px;  
  font-size: 12px;  
  font-weight: 600;  
  letter-spacing: 0.3px;  
}

.badge-indigo {  
  background: rgba(99, 102, 241, 0.15);  
  color: \#818cf8;  
  border: 1px solid rgba(99, 102, 241, 0.3);  
}

.badge-sky {  
  background: rgba(56, 189, 248, 0.15);  
  color: var(--accent-sky);  
  border: 1px solid rgba(56, 189, 248, 0.3);  
}

/\* Cards & Layout \*/  
.card {  
  background: var(--bg-card);  
  border: 1px solid var(--border-color);  
  border-radius: 12px;  
  padding: 24px;  
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);  
}

.card-title {  
  font-size: 16px;  
  font-weight: 700;  
  margin-bottom: 16px;  
  display: flex;  
  align-items: center;  
  justify-content: space-between;  
  color: \#fff;  
  border-bottom: 1px solid rgba(255, 255, 255, 0.05);  
  padding-bottom: 10px;  
}

.main-grid {  
  display: grid;  
  grid-template-columns: 1fr 1fr;  
  gap: 24px;  
  margin-bottom: 30px;  
}

@media (max-width: 960px) {  
  .main-grid {  
    grid-template-columns: 1fr;  
  }  
}

/\* Forms \*/  
.form-group {  
  margin-bottom: 18px;  
}

.form-label {  
  display: block;  
  font-size: 13px;  
  font-weight: 600;  
  color: var(--text-muted);  
  margin-bottom: 6px;  
}

.form-control {  
  width: 100%;  
  padding: 10px 14px;  
  background: var(--bg-input);  
  border: 1px solid var(--border-color);  
  border-radius: 8px;  
  color: var(--text-main);  
  font-size: 14px;  
  font-family: var(--font-mono);  
  transition: all 0.2s ease;  
}

.form-control:focus {  
  outline: none;  
  border-color: var(--border-active);  
  box-shadow: 0 0 12px rgba(99, 102, 241, 0.25);  
}

/\* Cert & Metadata Box \*/  
.cert-box {  
  background: var(--bg-input);  
  border: 1px solid var(--border-color);  
  border-radius: 8px;  
  padding: 14px;  
  font-size: 12px;  
  line-height: 1.6;  
  margin-top: 10px;  
}

.cert-field {  
  display: flex;  
  margin-bottom: 6px;  
}

.cert-label {  
  color: var(--text-muted);  
  width: 140px;  
  flex-shrink: 0;  
  font-weight: 600;  
}

.cert-val {  
  font-family: var(--font-mono);  
  color: \#38bdf8;  
  word-break: break-all;  
}

/\* Scorecard \*/  
.score-banner {  
  display: flex;  
  align-items: center;  
  justify-content: space-between;  
  background: var(--bg-input);  
  border: 1px solid var(--border-color);  
  border-radius: 10px;  
  padding: 16px 20px;  
  margin-bottom: 20px;  
}

.score-left {  
  display: flex;  
  align-items: center;  
  gap: 16px;  
}

.grade-badge {  
  width: 56px;  
  height: 56px;  
  border-radius: 50%;  
  display: flex;  
  align-items: center;  
  justify-content: center;  
  font-size: 24px;  
  font-weight: 800;  
  color: \#fff;  
}

.grade-a {  
  background: linear-gradient(135deg, \#10b981, \#059669);  
  box-shadow: 0 0 20px rgba(16, 185, 129, 0.4);  
}

.grade-b {  
  background: linear-gradient(135deg, \#6366f1, \#4f46e5);  
}

.grade-c {  
  background: linear-gradient(135deg, \#f59e0b, \#d97706);  
}

.grade-f {  
  background: linear-gradient(135deg, \#ef4444, \#dc2626);  
  box-shadow: 0 0 20px rgba(239, 68, 68, 0.4);  
}

.score-stats h3 {  
  font-size: 18px;  
  font-weight: 700;  
}

.score-stats p {  
  font-size: 12px;  
  color: var(--text-muted);  
}

.audit-list {  
  display: flex;  
  flex-direction: column;  
  gap: 10px;  
  max-height: 480px;  
  overflow-y: auto;  
  padding-right: 4px;  
}

.audit-item {  
  background: var(--bg-input);  
  border: 1px solid var(--border-color);  
  border-radius: 8px;  
  padding: 12px;  
  display: flex;  
  flex-direction: column;  
  gap: 4px;  
}

.audit-item.pass { border-left: 4px solid var(--accent-emerald); }  
.audit-item.warn { border-left: 4px solid var(--accent-yellow); }  
.audit-item.fail { border-left: 4px solid var(--accent-red); }

.audit-header-line {  
  display: flex;  
  justify-content: space-between;  
  align-items: center;  
}

.audit-title {  
  font-size: 13px;  
  font-weight: 700;  
  color: \#fff;  
}

.audit-tag {  
  font-size: 10px;  
  font-weight: 700;  
  padding: 2px 6px;  
  border-radius: 4px;  
}

.tag-pass { background: rgba(16, 185, 129, 0.2); color: var(--accent-emerald); }  
.tag-warn { background: rgba(245, 158, 11, 0.2); color: var(--accent-yellow); }  
.tag-fail { background: rgba(239, 68, 68, 0.2); color: var(--accent-red); }

.audit-desc {  
  font-size: 12px;  
  color: var(--text-muted);  
}

.audit-remed {  
  font-size: 11px;  
  color: \#fca5a5;  
  background: rgba(239, 68, 68, 0.08);  
  padding: 6px 8px;  
  border-radius: 4px;  
  margin-top: 4px;  
  font-family: var(--font-mono);  
}

/\* Simulator Panel \*/  
.sim-panel {  
  background: \#050a14;  
  border: 1px solid var(--border-color);  
  border-radius: 12px;  
  padding: 24px;  
  margin-bottom: 30px;  
}

.sim-controls {  
  display: flex;  
  gap: 12px;  
  margin-bottom: 20px;  
  flex-wrap: wrap;  
}

.sim-btn {  
  padding: 8px 16px;  
  border-radius: 6px;  
  font-size: 13px;  
  font-weight: 600;  
  cursor: pointer;  
  border: 1px solid transparent;  
  transition: all 0.2s;  
}

.sim-btn-danger {  
  background: rgba(239, 68, 68, 0.15);  
  border-color: rgba(239, 68, 68, 0.4);  
  color: \#f87171;  
}

.sim-btn-danger:hover, .sim-btn-danger.active {  
  background: var(--accent-red);  
  color: \#fff;  
}

.sim-btn-success {  
  background: rgba(16, 185, 129, 0.15);  
  border-color: rgba(16, 185, 129, 0.4);  
  color: \#34d399;  
}

.sim-btn-success:hover, .sim-btn-success.active {  
  background: var(--accent-emerald);  
  color: \#fff;  
}

.sim-terminal-log {  
  background: \#030712;  
  border: 1px solid \#1f2937;  
  border-radius: 8px;  
  padding: 16px;  
  font-family: var(--font-mono);  
  font-size: 12px;  
  max-height: 280px;  
  overflow-y: auto;  
  line-height: 1.7;  
}

.log-line { margin-bottom: 8px; }  
.log-step { color: \#818cf8; font-weight: 700; }  
.log-warn { color: \#f87171; }  
.log-pass { color: \#34d399; }  
.log-info { color: \#cbd5e1; }

/\* Tabs & Backend Code Output \*/  
.tabs {  
  display: flex;  
  gap: 6px;  
  border-bottom: 1px solid var(--border-color);  
  margin-bottom: 16px;  
  overflow-x: auto;  
}

.tab-btn {  
  background: transparent;  
  border: none;  
  border-bottom: 2px solid transparent;  
  color: var(--text-muted);  
  padding: 8px 16px;  
  font-size: 13px;  
  font-weight: 600;  
  cursor: pointer;  
  transition: all 0.2s;  
  white-space: nowrap;  
}

.tab-btn:hover { color: \#fff; }  
.tab-btn.active {  
  color: var(--accent-indigo);  
  border-bottom-color: var(--accent-indigo);  
}

.code-container {  
  position: relative;  
  background: \#040812;  
  border: 1px solid var(--border-color);  
  border-radius: 8px;  
  padding: 18px;  
}

.code-container pre {  
  margin: 0;  
  font-family: var(--font-mono);  
  font-size: 12px;  
  color: \#e2e8f0;  
  overflow-x: auto;  
  line-height: 1.6;  
}

.code-copy-btn {  
  position: absolute;  
  top: 12px;  
  right: 12px;  
}

.copy-btn {  
  background: rgba(99, 102, 241, 0.15);  
  border: 1px solid rgba(99, 102, 241, 0.3);  
  color: \#fff;  
  padding: 6px 12px;  
  border-radius: 6px;  
  font-size: 12px;  
  cursor: pointer;  
  font-weight: 600;  
  transition: all 0.2s ease;  
}

.copy-btn:hover { background: var(--accent-indigo); }

footer {  
  text-align: center;  
  margin-top: 40px;  
  padding-top: 20px;  
  border-top: 1px solid var(--border-color);  
  color: var(--text-dim);  
  font-size: 12px;  
}  
