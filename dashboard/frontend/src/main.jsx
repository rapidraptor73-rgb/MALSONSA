import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import "./styles.css";

const API = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

const severityOrder = ["critical", "high", "medium", "low", "info"];

function severityClass(value) {
  return `severity severity-${String(value || "info").toLowerCase()}`;
}

function fmtTime(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString();
}

function MetricCard({ title, value, sub }) {
  return (
    <div className="metric-card">
      <div className="metric-title">{title}</div>
      <div className="metric-value">{value ?? "-"}</div>
      <div className="metric-sub">{sub}</div>
    </div>
  );
}

function Sidebar({ active, setActive }) {
  const items = [
    ["dashboard", "통합 대시보드"],
    ["events", "이벤트 탐색"],
    ["siem", "SIEM 관제 사이트"],
  ];

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">SOC</div>
        <div>
          <strong>Unified SIEM</strong>
          <span>Security Operations</span>
        </div>
      </div>

      <nav>
        {items.map(([key, label]) => (
          <button
            key={key}
            className={active === key ? "nav-item active" : "nav-item"}
            onClick={() => setActive(key)}
          >
            {label}
          </button>
        ))}
      </nav>

      <div className="sidebar-note">
        DB 위치가 변경되어도 Backend의 DATABASE_URL만 수정
      </div>
    </aside>
  );
}

function Dashboard({ hours, setHours }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    setError("");
    fetch(`${API}/api/overview?hours=${hours}`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(setData)
      .catch((e) => setError(e.message));
  }, [hours]);

  if (error) return <div className="error-box">API 오류: {error}</div>;
  if (!data) return <div className="loading">대시보드 데이터 로딩 중...</div>;

  const severityData = severityOrder.map((name) => ({
    name,
    count: data.by_severity.find((x) => x.name.toLowerCase() === name)?.count || 0,
  }));

  return (
    <>
      <div className="page-head">
        <div>
          <h1>통합 SIEM 대시보드</h1>
          <p>공통 이벤트 DB 기준 통합 보안 현황</p>
        </div>
        <select value={hours} onChange={(e) => setHours(Number(e.target.value))}>
          <option value={1}>최근 1시간</option>
          <option value={6}>최근 6시간</option>
          <option value={24}>최근 24시간</option>
          <option value={72}>최근 3일</option>
          <option value={168}>최근 7일</option>
        </select>
      </div>

      <section className="metrics">
        <MetricCard title="전체 이벤트" value={data.total_events} sub={`최근 ${hours}시간`} />
        <MetricCard title="Critical" value={data.critical_events} sub="최우선 확인 대상" />
        <MetricCard title="High" value={data.high_events} sub="고위험 이벤트" />
        <MetricCard title="고유 Source IP" value={data.unique_src_ips} sub="관측된 출발지" />
      </section>

      <section className="grid-2">
        <div className="panel">
          <h2>Severity 분포</h2>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={severityData}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="name" />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                  {severityData.map((_, i) => <Cell key={i} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="panel">
          <h2>수집 제품 비중</h2>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height={280}>
              <PieChart>
                <Pie
                  data={data.by_product}
                  dataKey="count"
                  nameKey="name"
                  outerRadius={95}
                  innerRadius={55}
                  label
                />
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>

      <section className="panel">
        <h2>공격 / 이벤트 카테고리</h2>
        <div className="category-list">
          {data.by_category.map((x) => (
            <div className="category-row" key={x.name}>
              <span>{x.name}</span>
              <strong>{x.count}</strong>
            </div>
          ))}
        </div>
      </section>

      <section className="panel">
        <div className="panel-title-row">
          <h2>최근 이벤트</h2>
          <span>{data.recent_events.length}건 표시</span>
        </div>
        <EventTable rows={data.recent_events} />
      </section>
    </>
  );
}

function EventTable({ rows }) {
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>시간</th>
            <th>제품</th>
            <th>심각도</th>
            <th>분류</th>
            <th>Source IP</th>
            <th>Destination IP</th>
            <th>Rule</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id}>
              <td>{fmtTime(row.event_time)}</td>
              <td>{row.product}</td>
              <td><span className={severityClass(row.severity)}>{row.severity}</span></td>
              <td>{row.category}</td>
              <td>{row.src_ip || "-"}</td>
              <td>{row.dst_ip || "-"}</td>
              <td>{row.rule_name || "-"}</td>
              <td className="message-cell">{row.message}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function EventExplorer({ hours }) {
  const [rows, setRows] = useState([]);
  const [sources, setSources] = useState({ products: [], categories: [], severities: [] });
  const [filters, setFilters] = useState({
    severity: "",
    product: "",
    category: "",
    ip: "",
    q: "",
  });

  useEffect(() => {
    fetch(`${API}/api/sources`).then((r) => r.json()).then(setSources);
  }, []);

  const query = useMemo(() => {
    const p = new URLSearchParams({ hours: String(hours), limit: "300" });
    Object.entries(filters).forEach(([k, v]) => v && p.set(k, v));
    return p.toString();
  }, [filters, hours]);

  useEffect(() => {
    fetch(`${API}/api/events?${query}`)
      .then((r) => r.json())
      .then(setRows);
  }, [query]);

  function update(key, value) {
    setFilters((f) => ({ ...f, [key]: value }));
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>이벤트 탐색</h1>
          <p>DB에 적재된 보안 이벤트 검색 / 필터</p>
        </div>
      </div>

      <section className="panel">
        <div className="filters">
          <select value={filters.severity} onChange={(e) => update("severity", e.target.value)}>
            <option value="">전체 심각도</option>
            {sources.severities.map((x) => <option key={x}>{x}</option>)}
          </select>

          <select value={filters.product} onChange={(e) => update("product", e.target.value)}>
            <option value="">전체 제품</option>
            {sources.products.map((x) => <option key={x}>{x}</option>)}
          </select>

          <select value={filters.category} onChange={(e) => update("category", e.target.value)}>
            <option value="">전체 카테고리</option>
            {sources.categories.map((x) => <option key={x}>{x}</option>)}
          </select>

          <input
            placeholder="IP 정확히 입력"
            value={filters.ip}
            onChange={(e) => update("ip", e.target.value)}
          />

          <input
            placeholder="메시지 / 룰 / 사용자 검색"
            value={filters.q}
            onChange={(e) => update("q", e.target.value)}
          />
        </div>

        <div className="result-count">{rows.length}건</div>
        <EventTable rows={rows} />
      </section>
    </>
  );
}

function SiemSites() {
  const [links, setLinks] = useState([]);

  useEffect(() => {
    fetch(`${API}/api/siem-links`)
      .then((r) => r.json())
      .then(setLinks);
  }, []);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>SIEM 관제 사이트</h1>
          <p>각 제품별 상세 관제 화면으로 이동</p>
        </div>
      </div>

      <div className="site-grid">
        {links.map((item) => (
          <div className="site-card" key={item.name}>
            <div>
              <h3>{item.name}</h3>
              <p>{item.enabled ? item.url : "URL 미설정"}</p>
            </div>

            {item.enabled ? (
              <a href={item.url} target="_blank" rel="noreferrer">
                관제 화면 열기
              </a>
            ) : (
              <button disabled>설정 필요</button>
            )}
          </div>
        ))}
      </div>
    </>
  );
}

function App() {
  const [active, setActive] = useState("dashboard");
  const [hours, setHours] = useState(24);

  return (
    <div className="app-shell">
      <Sidebar active={active} setActive={setActive} />
      <main className="content">
        {active === "dashboard" && <Dashboard hours={hours} setHours={setHours} />}
        {active === "events" && <EventExplorer hours={hours} />}
        {active === "siem" && <SiemSites />}
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
