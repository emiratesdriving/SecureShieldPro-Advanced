import React from 'react';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  LineChart,
  Line,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer
} from 'recharts';
import {
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  ChartBarIcon,
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon
} from '@heroicons/react/24/outline';

interface SecurityMetrics {
  vulnerabilities: Array<{
    severity: string;
    count: number;
    color: string;
  }>;
  riskTrends: Array<{
    date: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
  }>;
  complianceStatus: Array<{
    framework: string;
    score: number;
    target: number;
  }>;
  assetDistribution: Array<{
    type: string;
    count: number;
    risk_score: number;
  }>;
  threatIntelligence: Array<{
    date: string;
    blocked_threats: number;
    suspicious_activities: number;
    false_positives: number;
  }>;
}

const SecurityDashboard: React.FC = () => {
  // Mock data for comprehensive security dashboard
  const securityMetrics: SecurityMetrics = {
    vulnerabilities: [
      { severity: 'Critical', count: 12, color: '#dc2626' },
      { severity: 'High', count: 34, color: '#ea580c' },
      { severity: 'Medium', count: 67, color: '#d97706' },
      { severity: 'Low', count: 123, color: '#65a30d' },
      { severity: 'Info', count: 45, color: '#2563eb' }
    ],
    riskTrends: [
      { date: '2025-09-01', critical: 15, high: 45, medium: 78, low: 120 },
      { date: '2025-09-05', critical: 18, high: 52, medium: 82, low: 115 },
      { date: '2025-09-10', critical: 14, high: 48, medium: 75, low: 125 },
      { date: '2025-09-15', critical: 12, high: 34, medium: 67, low: 123 },
      { date: '2025-09-18', critical: 8, high: 28, medium: 62, low: 130 }
    ],
    complianceStatus: [
      { framework: 'NIST CSF', score: 87, target: 95 },
      { framework: 'SOC 2', score: 92, target: 90 },
      { framework: 'ISO 27001', score: 78, target: 85 },
      { framework: 'PCI DSS', score: 94, target: 90 },
      { framework: 'GDPR', score: 89, target: 95 }
    ],
    assetDistribution: [
      { type: 'Servers', count: 45, risk_score: 7.2 },
      { type: 'Workstations', count: 67, risk_score: 4.8 },
      { type: 'Databases', count: 8, risk_score: 8.9 },
      { type: 'Network Devices', count: 12, risk_score: 6.1 },
      { type: 'Applications', count: 23, risk_score: 5.7 },
      { type: 'Cloud Services', count: 15, risk_score: 3.4 }
    ],
    threatIntelligence: [
      { date: '2025-09-14', blocked_threats: 234, suspicious_activities: 456, false_positives: 12 },
      { date: '2025-09-15', blocked_threats: 189, suspicious_activities: 523, false_positives: 8 },
      { date: '2025-09-16', blocked_threats: 267, suspicious_activities: 401, false_positives: 15 },
      { date: '2025-09-17', blocked_threats: 198, suspicious_activities: 478, false_positives: 6 },
      { date: '2025-09-18', blocked_threats: 312, suspicious_activities: 567, false_positives: 9 }
    ]
  };

  // Calculate summary statistics
  const totalVulnerabilities = securityMetrics.vulnerabilities.reduce((sum, v) => sum + v.count, 0);
  const criticalVulns = securityMetrics.vulnerabilities.find(v => v.severity === 'Critical')?.count || 0;
  const totalAssets = securityMetrics.assetDistribution.reduce((sum, a) => sum + a.count, 0);
  const avgComplianceScore = Math.round(
    securityMetrics.complianceStatus.reduce((sum, c) => sum + c.score, 0) / 
    securityMetrics.complianceStatus.length
  );

  // Risk trend analysis
  const latestRisk = securityMetrics.riskTrends[securityMetrics.riskTrends.length - 1];
  const previousRisk = securityMetrics.riskTrends[securityMetrics.riskTrends.length - 2];
  const riskChange = latestRisk.critical - previousRisk.critical;

  return (
    <div className="space-y-6 p-6 bg-gray-50 min-h-screen">
      {/* Header */}
      <div className="border-b border-gray-200 pb-4">
        <h1 className="text-3xl font-bold text-gray-900">Security Dashboard</h1>
        <p className="mt-2 text-sm text-gray-600">
          Real-time security metrics, risk analysis, and compliance monitoring
        </p>
      </div>

      {/* Key Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <ExclamationTriangleIcon className="h-6 w-6 text-red-600" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Critical Vulnerabilities</dt>
                  <dd className="flex items-baseline">
                    <div className="text-2xl font-semibold text-gray-900">{criticalVulns}</div>
                    <div className="ml-2 flex items-baseline text-sm font-semibold">
                      {riskChange < 0 ? (
                        <ArrowTrendingDownIcon className="h-4 w-4 text-green-500 mr-1" />
                      ) : (
                        <ArrowTrendingUpIcon className="h-4 w-4 text-red-500 mr-1" />
                      )}
                      <span className={riskChange < 0 ? 'text-green-600' : 'text-red-600'}>
                        {Math.abs(riskChange)}
                      </span>
                    </div>
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <ShieldCheckIcon className="h-6 w-6 text-blue-600" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Total Assets</dt>
                  <dd className="text-2xl font-semibold text-gray-900">{totalAssets}</dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <ChartBarIcon className="h-6 w-6 text-green-600" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Avg Compliance Score</dt>
                  <dd className="text-2xl font-semibold text-gray-900">{avgComplianceScore}%</dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <div className="h-6 w-6 bg-purple-600 rounded-full flex items-center justify-center">
                  <span className="text-xs font-bold text-white">{totalVulnerabilities}</span>
                </div>
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Total Vulnerabilities</dt>
                  <dd className="text-2xl font-semibold text-gray-900">{totalVulnerabilities}</dd>
                </dl>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Vulnerability Distribution */}
        <div className="bg-white p-6 rounded-lg shadow">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Vulnerability Distribution</h3>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={securityMetrics.vulnerabilities}
                  cx="50%"
                  cy="50%"
                  outerRadius={120}
                  fill="#8884d8"
                  dataKey="count"
                  label={({ severity, count }) => `${severity}: ${count}`}
                >
                  {securityMetrics.vulnerabilities.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Risk Trends */}
        <div className="bg-white p-6 rounded-lg shadow">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Risk Trends (Last 30 Days)</h3>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={securityMetrics.riskTrends}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" tickFormatter={(date) => new Date(date).toLocaleDateString()} />
                <YAxis />
                <Tooltip labelFormatter={(date) => new Date(date).toLocaleDateString()} />
                <Legend />
                <Area type="monotone" dataKey="critical" stackId="1" stroke="#dc2626" fill="#dc2626" />
                <Area type="monotone" dataKey="high" stackId="1" stroke="#ea580c" fill="#ea580c" />
                <Area type="monotone" dataKey="medium" stackId="1" stroke="#d97706" fill="#d97706" />
                <Area type="monotone" dataKey="low" stackId="1" stroke="#65a30d" fill="#65a30d" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Compliance Status */}
        <div className="bg-white p-6 rounded-lg shadow">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Compliance Framework Status</h3>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={securityMetrics.complianceStatus} layout="horizontal">
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis type="number" domain={[0, 100]} />
                <YAxis dataKey="framework" type="category" width={80} />
                <Tooltip formatter={(value) => [`${value}%`, 'Score']} />
                <Legend />
                <Bar dataKey="score" fill="#2563eb" name="Current Score" />
                <Bar dataKey="target" fill="#e5e7eb" name="Target Score" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Asset Distribution */}
        <div className="bg-white p-6 rounded-lg shadow">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Asset Distribution & Risk Scores</h3>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={securityMetrics.assetDistribution}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="type" angle={-45} textAnchor="end" height={80} />
                <YAxis yAxisId="left" />
                <YAxis yAxisId="right" orientation="right" />
                <Tooltip />
                <Legend />
                <Bar yAxisId="left" dataKey="count" fill="#3b82f6" name="Asset Count" />
                <Line yAxisId="right" dataKey="risk_score" stroke="#ef4444" name="Risk Score" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Threat Intelligence Timeline */}
      <div className="bg-white p-6 rounded-lg shadow">
        <h3 className="text-lg font-medium text-gray-900 mb-4">Threat Intelligence Activity (Last 5 Days)</h3>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={securityMetrics.threatIntelligence}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="date" tickFormatter={(date) => new Date(date).toLocaleDateString()} />
              <YAxis />
              <Tooltip labelFormatter={(date) => new Date(date).toLocaleDateString()} />
              <Legend />
              <Line 
                type="monotone" 
                dataKey="blocked_threats" 
                stroke="#dc2626" 
                strokeWidth={3}
                name="Blocked Threats" 
              />
              <Line 
                type="monotone" 
                dataKey="suspicious_activities" 
                stroke="#f59e0b" 
                strokeWidth={2}
                name="Suspicious Activities" 
              />
              <Line 
                type="monotone" 
                dataKey="false_positives" 
                stroke="#6b7280" 
                strokeWidth={1}
                name="False Positives" 
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Security Score Summary */}
      <div className="bg-white p-6 rounded-lg shadow">
        <h3 className="text-lg font-medium text-gray-900 mb-4">Security Posture Summary</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="text-center">
            <div className="text-3xl font-bold text-green-600">87%</div>
            <div className="text-sm text-gray-500">Overall Security Score</div>
            <div className="mt-2 w-full bg-gray-200 rounded-full h-2">
              <div className="bg-green-600 h-2 rounded-full" style={{ width: '87%' }}></div>
            </div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-blue-600">92%</div>
            <div className="text-sm text-gray-500">Compliance Coverage</div>
            <div className="mt-2 w-full bg-gray-200 rounded-full h-2">
              <div className="bg-blue-600 h-2 rounded-full" style={{ width: '92%' }}></div>
            </div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-purple-600">78%</div>
            <div className="text-sm text-gray-500">Threat Detection Rate</div>
            <div className="mt-2 w-full bg-gray-200 rounded-full h-2">
              <div className="bg-purple-600 h-2 rounded-full" style={{ width: '78%' }}></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SecurityDashboard;