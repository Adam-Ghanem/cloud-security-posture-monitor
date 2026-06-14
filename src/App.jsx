import { AlertTriangle, CheckCircle2, Cloud, Lock, ShieldCheck, Server } from 'lucide-react';
import findings from '../data/sample-findings.json';

const severityWeight = {
  Critical: 25,
  High: 15,
  Medium: 8,
  Low: 3
};

function calculateScore(items) {
  const penalty = items.reduce((total, item) => total + severityWeight[item.severity], 0);
  return Math.max(0, 100 - penalty);
}

function countBySeverity(items, severity) {
  return items.filter((item) => item.severity === severity).length;
}

function getSeverityClass(severity) {
  return severity.toLowerCase();
}

export default function App() {
  const score = calculateScore(findings);
  const criticalCount = countBySeverity(findings, 'Critical');
  const highCount = countBySeverity(findings, 'High');
  const mediumCount = countBySeverity(findings, 'Medium');
  const lowCount = countBySeverity(findings, 'Low');

  return (
    <main className="page">
      <section className="hero">
        <div>
          <p className="eyebrow">Cloud Security Posture Monitor</p>
          <h1>Detect cloud misconfigurations before they become incidents.</h1>
          <p className="heroText">
            A defensive dashboard for tracking exposed services, weak IAM settings,
            missing encryption, and logging gaps across cloud environments.
          </p>
        </div>
        <div className="scoreCard">
          <ShieldCheck size={42} />
          <span>Posture Score</span>
          <strong>{score}/100</strong>
          <p>{score >= 80 ? 'Healthy posture' : 'Needs remediation'}</p>
        </div>
      </section>

      <section className="statsGrid">
        <article className="stat critical"><AlertTriangle /> <span>Critical</span><strong>{criticalCount}</strong></article>
        <article className="stat high"><AlertTriangle /> <span>High</span><strong>{highCount}</strong></article>
        <article className="stat medium"><Server /> <span>Medium</span><strong>{mediumCount}</strong></article>
        <article className="stat low"><CheckCircle2 /> <span>Low</span><strong>{lowCount}</strong></article>
      </section>

      <section className="panel">
        <div className="panelHeader">
          <div>
            <h2>Active Findings</h2>
            <p>Prioritized cloud posture issues with simple remediation guidance.</p>
          </div>
          <Cloud />
        </div>

        <div className="findingsList">
          {findings.map((finding) => (
            <article className="finding" key={finding.id}>
              <div className="findingTop">
                <span className={`badge ${getSeverityClass(finding.severity)}`}>{finding.severity}</span>
                <span className="service">{finding.provider} · {finding.service}</span>
              </div>
              <h3>{finding.title}</h3>
              <p>{finding.description}</p>
              <div className="remediation">
                <Lock size={18} />
                <span>{finding.remediation}</span>
              </div>
            </article>
          ))}
        </div>
      </section>
    </main>
  );
}
