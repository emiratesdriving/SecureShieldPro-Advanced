'use client';

import React, { useState } from 'react';
import FileUploadScanner from '@/components/FileUploadScanner';
import SimpleChart from '@/components/SimpleChart';
import { 
  ShieldCheckIcon, 
  ExclamationTriangleIcon, 
  DocumentCheckIcon,
  ChartBarIcon,
  ClockIcon,
  UserGroupIcon,
  BoltIcon,
  FireIcon,
  CloudArrowUpIcon
} from '@heroicons/react/24/outline';

// Statistics Cards Component
const StatsCard = ({ title, value, change, icon: Icon, color }: any) => (
  <div className="bg-white/10 backdrop-blur-xl rounded-2xl p-6 border border-white/20 shadow-xl hover:shadow-2xl transition-all duration-300 hover:bg-white/15">
    <div className="flex items-center justify-between">
      <div>
        <p className="text-gray-300 text-sm font-medium mb-1">{title}</p>
        <p className="text-3xl font-bold text-white mb-2">{value}</p>
        <p className={`text-sm font-medium ${change.startsWith('+') ? 'text-green-400' : change.startsWith('-') ? 'text-red-400' : 'text-gray-400'}`}>
          {change}
        </p>
      </div>
      <div className={`p-3 rounded-xl bg-gradient-to-r ${color} shadow-lg`}>
        <Icon className="h-6 w-6 text-white" />
      </div>
    </div>
  </div>
);

// Recent Activity Component
const ActivityCard = ({ title, description, time, type }: any) => (
  <div className="flex items-start space-x-3 p-4 rounded-lg bg-white/5 border border-white/10 hover:bg-white/10 transition-all duration-200">
    <div className={`p-2 rounded-lg ${
      type === 'warning' ? 'bg-yellow-500/20 text-yellow-400' :
      type === 'error' ? 'bg-red-500/20 text-red-400' :
      type === 'success' ? 'bg-green-500/20 text-green-400' :
      'bg-blue-500/20 text-blue-400'
    }`}>
      {type === 'warning' && <ExclamationTriangleIcon className="h-4 w-4" />}
      {type === 'error' && <FireIcon className="h-4 w-4" />}
      {type === 'success' && <ShieldCheckIcon className="h-4 w-4" />}
      {type === 'info' && <BoltIcon className="h-4 w-4" />}
    </div>
    <div className="flex-1 min-w-0">
      <p className="text-sm font-medium text-white truncate">{title}</p>
      <p className="text-sm text-gray-400 mt-1">{description}</p>
      <p className="text-xs text-gray-500 mt-1 flex items-center">
        <ClockIcon className="h-3 w-3 mr-1" />
        {time}
      </p>
    </div>
  </div>
);

export default function Dashboard() {
  const [showFileUpload, setShowFileUpload] = useState(false);

  // Chart data
  const threatLevelData = {
    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
    values: [2, 12, 45, 78, 23],
    colors: ['#EF4444', '#F59E0B', '#8B5CF6', '#10B981', '#3B82F6']
  };

  const scanHistoryData = {
    labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
    values: [45, 52, 38, 65, 71, 44, 58],
    colors: ['#3B82F6']
  };

  const complianceData = {
    labels: ['SOC 2', 'ISO 27001', 'PCI DSS', 'GDPR'],
    values: [98, 94, 89, 96],
    colors: ['#10B981', '#3B82F6', '#8B5CF6', '#F59E0B']
  };

  const stats = [
    {
      title: 'Security Score',
      value: '94/100',
      change: '+2.1%',
      icon: ShieldCheckIcon,
      color: 'from-green-500 to-emerald-600'
    },
    {
      title: 'Active Vulnerabilities',
      value: '12',
      change: '-23.5%',
      icon: ExclamationTriangleIcon,
      color: 'from-red-500 to-rose-600'
    },
    {
      title: 'Compliance Score',
      value: '98%',
      change: '+5.4%',
      icon: DocumentCheckIcon,
      color: 'from-blue-500 to-indigo-600'
    },
    {
      title: 'Scans This Month',
      value: '1,247',
      change: '+12.3%',
      icon: ChartBarIcon,
      color: 'from-purple-500 to-violet-600'
    }
  ];

  const recentActivity = [
    {
      title: 'High-Risk Vulnerability Detected',
      description: 'SQL injection vulnerability found in user authentication module',
      time: '2 minutes ago',
      type: 'error'
    },
    {
      title: 'SAST Scan Completed',
      description: 'Automated static analysis completed for main application',
      time: '15 minutes ago',
      type: 'success'
    },
    {
      title: 'Compliance Check Failed',
      description: 'GDPR compliance check failed for data retention policy',
      time: '1 hour ago',
      type: 'warning'
    },
    {
      title: 'New Security Policy Applied',
      description: 'Updated firewall rules have been deployed across all environments',
      time: '2 hours ago',
      type: 'info'
    },
    {
      title: 'Vulnerability Patched',
      description: 'CVE-2024-1234 has been successfully patched in production',
      time: '3 hours ago',
      type: 'success'
    }
  ];

  return (
    <div className="space-y-6">
      {/* Welcome Section */}
      <div className="bg-gradient-to-r from-blue-500/20 to-purple-600/20 backdrop-blur-xl rounded-2xl p-8 border border-white/20 shadow-xl">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">
              Welcome to SecureShield Pro
            </h1>
            <p className="text-gray-300 text-lg">
              Your comprehensive security dashboard with AI-powered threat detection
            </p>
            <div className="flex items-center mt-4 space-x-6">
              <div className="flex items-center">
                <UserGroupIcon className="h-5 w-5 text-blue-400 mr-2" />
                <span className="text-gray-300">5 Active Users</span>
              </div>
              <div className="flex items-center">
                <ClockIcon className="h-5 w-5 text-green-400 mr-2" />
                <span className="text-gray-300">Last scan: 2 hours ago</span>
              </div>
            </div>
          </div>
          <div className="hidden lg:block">
            <div className="w-32 h-32 bg-gradient-to-r from-blue-400 to-purple-500 rounded-full flex items-center justify-center">
              <ShieldCheckIcon className="h-16 w-16 text-white" />
            </div>
          </div>
        </div>
      </div>

      {/* Statistics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {stats.map((stat, index) => (
          <StatsCard key={index} {...stat} />
        ))}
      </div>

      {/* Analytics Charts */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <SimpleChart 
          data={threatLevelData}
          type="doughnut"
          title="Threat Distribution"
        />
        <SimpleChart 
          data={scanHistoryData}
          type="line"
          title="Weekly Scan Activity"
        />
        <SimpleChart 
          data={complianceData}
          type="bar"
          title="Compliance Scores (%)"
        />
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Activity */}
        <div className="lg:col-span-2">
          <div className="bg-white/10 backdrop-blur-xl rounded-2xl p-6 border border-white/20 shadow-xl">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-bold text-white">Recent Activity</h2>
              <button className="text-blue-400 hover:text-blue-300 text-sm font-medium transition-colors">
                View All
              </button>
            </div>
            <div className="space-y-4">
              {recentActivity.map((activity, index) => (
                <ActivityCard key={index} {...activity} />
              ))}
            </div>
          </div>
        </div>

        {/* Quick Actions & Status */}
        <div className="space-y-6">
          {/* Quick Actions */}
          <div className="bg-white/10 backdrop-blur-xl rounded-2xl p-6 border border-white/20 shadow-xl">
            <h2 className="text-xl font-bold text-white mb-4">Quick Actions</h2>
            <div className="space-y-3">
              <button 
                onClick={() => setShowFileUpload(true)}
                className="w-full bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 text-white font-medium py-3 px-4 rounded-lg transition-all duration-200 shadow-lg hover:shadow-xl flex items-center justify-center"
              >
                <CloudArrowUpIcon className="h-5 w-5 mr-2" />
                Upload & Scan Files
              </button>
              <button className="w-full bg-gradient-to-r from-purple-500 to-purple-600 hover:from-purple-600 hover:to-purple-700 text-white font-medium py-3 px-4 rounded-lg transition-all duration-200 shadow-lg hover:shadow-xl">
                Generate Report
              </button>
              <button className="w-full bg-gradient-to-r from-green-500 to-green-600 hover:from-green-600 hover:to-green-700 text-white font-medium py-3 px-4 rounded-lg transition-all duration-200 shadow-lg hover:shadow-xl">
                Review Findings
              </button>
            </div>
          </div>

          {/* System Status */}
          <div className="bg-white/10 backdrop-blur-xl rounded-2xl p-6 border border-white/20 shadow-xl">
            <h2 className="text-xl font-bold text-white mb-4">System Status</h2>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-gray-300">Scanner Engine</span>
                <span className="flex items-center text-green-400">
                  <div className="w-2 h-2 bg-green-400 rounded-full mr-2"></div>
                  Online
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-300">AI Analysis</span>
                <span className="flex items-center text-green-400">
                  <div className="w-2 h-2 bg-green-400 rounded-full mr-2"></div>
                  Active
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-300">Database</span>
                <span className="flex items-center text-yellow-400">
                  <div className="w-2 h-2 bg-yellow-400 rounded-full mr-2"></div>
                  Connecting
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-300">API Gateway</span>
                <span className="flex items-center text-green-400">
                  <div className="w-2 h-2 bg-green-400 rounded-full mr-2"></div>
                  Healthy
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* File Upload Modal */}
      {showFileUpload && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-white/10 backdrop-blur-xl rounded-2xl p-6 border border-white/20 shadow-2xl max-w-2xl w-full max-h-[80vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-bold text-white">File Security Scanner</h2>
              <button
                onClick={() => setShowFileUpload(false)}
                className="text-gray-400 hover:text-white transition-colors"
                aria-label="Close modal"
              >
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <FileUploadScanner 
              onFileUploaded={(file, result) => {
                console.log('File uploaded and scanned:', file.name, result);
              }}
            />
          </div>
        </div>
      )}
    </div>
  );
}